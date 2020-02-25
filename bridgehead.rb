# frozen_string_literal: true

require 'simpleidn'
require 'parallel'
require 'openssl'
require 'socket'
require 'timeout'
require 'curb'
require 'csv'
require 'whois'
require 'whois-parser'
require 'resolv'

module Bridgehead
  class << self
    USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.52 Safari/537.36'

    def analyze(domains, threads = 16, timeout = 5)
      raise unless domains.is_a?(Array)

      # 国際化ドメインはPunycodeに変換しておく
      domains.map! { |item| item.merge(domain_name: SimpleIDN.to_ascii(item[:original_domain_name].strip)) }

      # 分析
      Parallel.map(domains, in_threads: threads, progress: { title: 'Analyzing URLs', output: $stderr }) do |item|
        item[:dns_records] = dns_records(item, timeout)
        if item[:dns_records] && !item[:dns_records].empty?
          item[:registrar] = registrar(item, timeout)
          item[:certificates] = ssl_certificates(item, timeout)
          item[:http] = http('http', item, timeout)
          item[:https] = http('https', item, timeout)
          item[:datetime] = Time.now
        end
        item
      end
    end

    def dump_to_csv(domain_info)
      CSV.generate(row_sep: "\r\n", col_sep: "\t") do |csv|
        csv << ['Domain',
                'Registrar (Beta)',
                'CNAME',
                'IPv4',
                'IPv6',
                'MX',
                'NS',
                'SSL',
                'CN',
                'O',
                'OU',
                'Cert Chain',
                'Is EV? (Beta)',
                'HTTP',
                'HTTPS',
                'Time']

        domain_info.each do |domain|
          next if domain.nil?

          if domain[:dns_records].nil? || domain[:dns_records].empty?
            csv << [domain[:original_domain_name]]
            next
          end

          dns_cname = domain[:dns_records].select { |record| record.class == Resolv::DNS::Resource::IN::CNAME }.map { |record| record.name.to_s }.join("\r\n")
          dns_ipv4 = domain[:dns_records].select { |record| record.class == Resolv::DNS::Resource::IN::A }.map { |record| record.address.to_s }.join("\r\n")
          dns_ipv6 = domain[:dns_records].select { |record| record.class == Resolv::DNS::Resource::IN::AAAA }.map { |record| record.address.to_s }.join("\r\n")
          dns_mx = domain[:dns_records].select { |record| record.class == Resolv::DNS::Resource::IN::MX }.map { |record| record.exchange.to_s }.join("\r\n")
          dns_ns = domain[:dns_records].select { |record| record.class == Resolv::DNS::Resource::IN::NS }.map { |record| record.name.to_s }.join("\r\n")

          # SSLサポート
          ssl_support = domain[:https] ? domain[:https][:ssl_support] : ''

          leaf_cert = {}
          if domain[:certificates]
            leaf_cert = domain[:certificates].first.subject.to_a.map { |item| { item[0] => item[1] } }.reduce({}) { |sum, item| sum.merge(item) }
            certs = domain[:certificates].map { |cert| "s:#{cert.subject}\r\ni:#{cert.issuer}" }.join("\r\n\r\n")
            is_ev = certs.include?('EV') || certs.include?('Extended') ? 'Yes' : 'No'
          end

          # 出力
          csv << [domain[:original_domain_name],
                  domain[:registrar],
                  dns_cname,
                  dns_ipv4,
                  dns_ipv6,
                  dns_mx,
                  dns_ns,
                  ssl_support,
                  leaf_cert['CN'],
                  leaf_cert['O'],
                  leaf_cert['OU'],
                  certs,
                  is_ev,
                  domain[:http].nil? ? '' : domain[:http][:status_code],
                  domain[:https].nil? ? '' : domain[:https][:status_code],
                  domain[:datetime]]
        end
      end
    end

    # DNSレコード取得
    def dns_records(domain, timeout)
      name_servers = %w[8.8.8.8 8.8.4.4]

      begin
        Timeout.timeout(timeout) do
          # ANYだとA, AAAAを返さないDNSがいるのでレコードタイプを指定して取得する
          Resolv::DNS.new(nameserver: name_servers).getresources(domain[:domain_name], Resolv::DNS::Resource::IN::SOA)
                     .concat(Resolv::DNS.new(nameserver: name_servers).getresources(domain[:domain_name], Resolv::DNS::Resource::IN::A))
                     .concat(Resolv::DNS.new(nameserver: name_servers).getresources(domain[:domain_name], Resolv::DNS::Resource::IN::AAAA))
                     .concat(Resolv::DNS.new(nameserver: name_servers).getresources(domain[:domain_name], Resolv::DNS::Resource::IN::CNAME))
                     .concat(Resolv::DNS.new(nameserver: name_servers).getresources(domain[:domain_name], Resolv::DNS::Resource::IN::MX))
                     .concat(Resolv::DNS.new(nameserver: name_servers).getresources(domain[:domain_name], Resolv::DNS::Resource::IN::NS))
        end
      rescue StandardError
        nil
      end
    end

    # ドメインレジストラ取得
    def registrar(domain, timeout)
      Timeout.timeout(timeout) do
        if domain[:dns_records].any? { |record| record.class == Resolv::DNS::Resource::IN::SOA }
          r_tmp = Whois.whois(domain[:domain_name]).parser
          r_tmp.registrar.name if r_tmp.registered? && r_tmp.registrar
        else
          r_tmp = Whois.whois(domain[:domain_name].sub(/.+?\./, '')).parser
          r_tmp.registrar.name if r_tmp.registered? && r_tmp.registrar
        end
      end
    rescue StandardError
      nil
    end

    # SSL証明書取得
    def ssl_certificates(domain, timeout)
      soc = nil
      ssl_socket = nil
      Timeout.timeout(timeout) do
        soc = TCPSocket.new(domain[:domain_name], 443)
      end
      Timeout.timeout(timeout) do
        ssl_socket = OpenSSL::SSL::SSLSocket.new(soc)
      end
      Timeout.timeout(timeout) do
        ssl_socket.hostname = domain[:domain_name]

        ssl_socket.connect
        ssl_socket.peer_cert_chain
      end
    rescue StandardError
      nil
    end

    # HTTP/HTTPS接続テスト
    def http(scheme, domain, timeout)
      # Aレコードがなかったら失敗
      if domain[:dns_records].nil? || domain[:dns_records].none? { |record| record.class == Resolv::DNS::Resource::IN::A }
        return nil
      end

      result = {}

      # HTTPSなのに証明書がなければ失敗
      if (scheme == 'https') && domain[:certificates].nil?
        result[:status_code] = '000 Connection Error'
        result[:ssl_support] = 'Unsupported (No certificates)'
        return result
      end

      # HTTP/HTTPSで接続する
      begin
        curl = Curl::Easy.new("#{scheme}://#{domain[:domain_name]}/")
        curl.headers['User-Agent'] = USER_AGENT
        curl.connect_timeout = timeout
        curl.timeout = timeout
        curl.perform

        result[:status_code] = curl.status

        # リダイレクト先があれば取得する
        location = curl.header_str.split("\r\n").select { |header| header.split(': ').first.casecmp('location').zero? }.first
        if location
          result[:location] = location.sub('Location: ', '').to_s
          result[:status_code] = "#{curl.status} (#{result[:location]})"
        else
          if curl.body_str.downcase.include?('http-equiv') && curl.body_str.downcase.include?('url=')
            result[:location] = 'HTML meta redirect'
            result[:status_code] = "#{curl.status} (#{result[:location]})"
          end
        end

        result[:ssl_support] = 'Supported' if scheme == 'https'
      rescue Curl::Err::SSLPeerCertificateError, Curl::Err::SSLCACertificateError
        result[:status_code] = '000 Connection Error'
        if scheme == 'https'
          result[:ssl_support] = 'Unsupported (Port 443 is opened but certificate is not valid)'
        end
      rescue Curl::Err::ConnectionFailedError, Curl::Err::RecvError, Curl::Err::SSLConnectError
        result[:status_code] = '000 Connection Error'
        if scheme == 'https'
          result[:ssl_support] = 'Unsupported (Port 443 is closed)'
        end
      rescue Curl::Err::TimeoutError
        result[:status_code] = '000 Connection Error'
        result[:ssl_support] = 'Timeout' if scheme == 'https'
      rescue Curl::Err::HostResolutionError
        result[:status_code] = 'Invalid hostname'
      rescue StandardError => e
        result[:status_code] = "Unknown error: #{e.message}"
      end

      result
    end
  end
end

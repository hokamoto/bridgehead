# frozen_string_literal: true

require './bridgehead'

urls = []
STDIN.each do |domain|
  urls.push({ original_domain_name: domain.strip })
end

puts Bridgehead.dump_to_csv(Bridgehead.analyze(urls))

FROM ruby:2.7.0-alpine3.11

WORKDIR /usr/src/app
COPY Gemfile Gemfile.lock ./

RUN apk update && \
    apk add --no-cache curl-dev make gcc libc-dev g++ && \
    bundle install && \
    rm -rf /usr/local/bundle/cache/* /usr/local/share/.cache/* /var/cache/* /tmp/* && \
    apk del make gcc libc-dev g++

COPY bridgehead.rb main.rb ./
ENTRYPOINT ["/usr/bin/env", "ruby", "./main.rb"]

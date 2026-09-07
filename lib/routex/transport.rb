# frozen_string_literal: true

require "net/http"
require "uri"
require_relative "errors"

module Routex
  # Raw HTTP result. Distinct from Routex::Response, which models a decoded
  # service response.
  HttpResponse = Struct.new(:status, :headers, :body, keyword_init: true)

  # Minimal HTTP surface. Swap in your own object responding to #execute to route
  # requests through an existing connection pool (Excon, Faraday, ...).
  class Transport
    DEFAULT_OPEN_TIMEOUT = 10
    DEFAULT_READ_TIMEOUT = 120

    def initialize(open_timeout: DEFAULT_OPEN_TIMEOUT, read_timeout: DEFAULT_READ_TIMEOUT)
      @open_timeout = open_timeout
      @read_timeout = read_timeout
    end

    def execute(method:, url:, headers: {}, body: nil)
      uri = URI.parse(url.to_s)
      request = build_request(method, uri, headers, body)

      response = Net::HTTP.start(uri.host, uri.port,
                                 use_ssl: uri.scheme == "https",
                                 open_timeout: @open_timeout,
                                 read_timeout: @read_timeout) { |http| http.request(request) }

      HttpResponse.new(
        status: response.code.to_i,
        headers: response.each_header.to_h,
        body: (response.body || "").b
      )
    rescue SystemCallError, Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError => e
      raise TransportError, "#{method} #{uri} failed: #{e.class}: #{e.message}"
    end

    private

    def build_request(method, uri, headers, body)
      klass = method == :post ? Net::HTTP::Post : Net::HTTP::Get
      request = klass.new(uri)
      headers.each { |name, value| request[name] = value }
      request.body = body if body
      request
    end
  end
end

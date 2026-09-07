# frozen_string_literal: true

require "json"
require "base64"
require_relative "errors"

module Routex
  # A signed service ticket. `raw` is the compact JWT that goes to the service;
  # `id` is the ticket id the gateway uses for sticky routing.
  Ticket = Struct.new(:service, :id, :raw, keyword_init: true) do
    def self.parse(raw)
      payload = raw.split(".")[1] or raise Error, "not a compact JWT"
      claims = JSON.parse(Base64.urlsafe_decode64(payload.ljust((payload.size + 3) / 4 * 4, "=")))
      data = claims.fetch("data")
      new(service: data.fetch("service"), id: data.fetch("id"), raw: raw)
    rescue JSON::ParserError, KeyError, ArgumentError => e
      raise Error, "malformed ticket: #{e.message}"
    end

    def to_s = raw
  end
end

# frozen_string_literal: true

require "json"
require "openssl"
require "securerandom"
require_relative "ticket"

module Routex
  # Issues the HS256 JWT service tickets a backend hands to a client.
  #
  # This runs wherever the API key secret lives -- your server, never a browser
  # or mobile app. Port of RoutexTicketIssuer.kt.
  class TicketIssuer
    DEFAULT_TTL = 15 * 60

    SERVICES = {
      accounts: "Accounts",
      balances: "Balances",
      transactions: "Transactions",
      transfer: "Transfer",
      collect_payment: "CollectPayment"
    }.freeze

    def initialize(api_key_id:, api_key_secret: nil, base64_secret: nil, ttl: DEFAULT_TTL, clock: -> { Time.now })
      raise ArgumentError, "api_key_id must not be blank" if api_key_id.to_s.strip.empty?

      @api_key_secret = api_key_secret || Base64.strict_decode64(base64_secret.to_s)
      raise ArgumentError, "api key secret must not be empty" if @api_key_secret.empty?
      raise ArgumentError, "ttl must be positive (got #{ttl})" unless ttl.positive?

      @api_key_id = api_key_id
      @ttl = ttl
      @clock = clock
    end

    SERVICES.each_key do |name|
      define_method(name) do |data: nil, ttl: nil, ticket_id: nil|
        issue(SERVICES.fetch(name), data: data, ttl: ttl, ticket_id: ticket_id)
      end
    end

    def issue(service, data: nil, ttl: nil, ticket_id: nil)
      ticket_id ||= SecureRandom.uuid
      expires_at = (@clock.call.to_i + (ttl || @ttl))
      claims = { data: { service: service, id: ticket_id, data: data }, exp: expires_at }
      Ticket.new(service: service, id: ticket_id, raw: sign(JSON.generate(claims)))
    end

    private

    def sign(claims_json)
      header = JSON.generate(alg: "HS256", typ: "JWT", kid: @api_key_id)
      signing_input = "#{b64(header)}.#{b64(claims_json)}"
      "#{signing_input}.#{b64(OpenSSL::HMAC.digest("SHA256", @api_key_secret, signing_input))}"
    end

    def b64(bytes) = Base64.urlsafe_encode64(bytes, padding: false)
  end
end

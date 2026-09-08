# frozen_string_literal: true

require "base64"
require "json"
require_relative "client_core"
require_relative "discovery"
require_relative "errors"
require_relative "settlement"
require_relative "transport"

module Routex
  # Client for the non-interactive (refresh) services.
  #
  # Use it to refresh data for a connection that already went through an
  # interactive consent, without prompting anyone. Compared to Routex::Client:
  #
  # - **Inputs.** Connection data from a successful interactive flow replaces the
  #   credentials. See https://docs.yaxi.tech/sessions.html.
  # - **Outputs.** Each call returns its payload directly in `#result` -- no JWT
  #   envelope and no interrupt branches to loop over.
  # - **Surface.** Read services only. Payments and transfers are inherently
  #   interactive and live on Routex::Client.
  #
  # Connection data can be rotated by the service, so persist `#connection_data`
  # from every response when it is present and use it for the next call.
  class RefreshClient
    include Discovery

    PRODUCTION_URL = "https://api.yaxi.tech"
    INTEGRATION_URL = "https://integration.yaxi.tech"

    # Without a user in session, banks cap how many requests a caller may make
    # and reject the excess with AccessExceededError. Declaring a user in session
    # lifts that cap; YAXI then forwards the user's IP to the bank.
    module UserInSession
      # The user's IP is this connection's own source IP.
      ON_THIS_CONNECTION = "connection"

      # The user is at the given IP address.
      def self.at(ip_address) = ip_address
    end

    # Non-interactive responses carry the payload directly, with an optionally
    # rotated session and connection data alongside it.
    Response = Struct.new(:result, :session, :connection_data, keyword_init: true)

    attr_reader :core
    attr_accessor :user_in_session

    def initialize(base_url: PRODUCTION_URL, transport: Transport.new,
                   requirements: Requirements::DEFAULT,
                   signing_keys: YaxiSystemVersionKeys::DEFAULT,
                   user_in_session: nil, core: nil)
      @user_in_session = user_in_session
      @core = core || ClientCore.new do
        Settlement.new(base_url: base_url, transport: transport,
                       requirements: requirements, signing_keys: signing_keys)
      end
    end

    def redirect_uri=(uri)
      @core.redirect_uri = uri
    end

    def accounts(ticket, connection_data:, session: nil, fields: nil, filter: nil)
      call(ticket, "accounts/non-interactive", connection_data, session,
           fields: fields || [], filter: filter)
    end

    def balances(ticket, connection_data:, accounts:, session: nil)
      call(ticket, "balances/non-interactive", connection_data, session, accounts: accounts)
    end

    # The account and period come from the ticket, not from here.
    def transactions(ticket, connection_data:, session: nil)
      call(ticket, "transactions/non-interactive", connection_data, session)
    end

    private

    def call(ticket, path, connection_data, session, **extra)
      body = JSON.generate(request_body(connection_data, session, extra))
      read_response(@core.request(ticket: ticket, path: path, body: body))
    end

    # Unlike the interactive envelope, absent values are omitted here rather than
    # sent as explicit nulls.
    def request_body(connection_data, session, extra)
      raise ArgumentError, "connection_data is required" if connection_data.nil? || connection_data.empty?

      body = { connectionData: Base64.strict_encode64(connection_data) }
      body[:session] = Base64.strict_encode64(session) if session
      body[:userInSession] = @user_in_session if @user_in_session
      body.merge(extra.reject { |_, value| value.nil? })
    end

    def read_response(bytes)
      json = JSON.parse(bytes)
      unless json.is_a?(Hash)
        raise ResponseError, "expected a non-interactive response object, got #{json.class}"
      end

      Response.new(
        result: json["result"],
        session: decode(json["session"], "session"),
        connection_data: decode(json["connectionData"], "connectionData")
      )
    rescue JSON::ParserError => e
      raise ResponseError, "malformed non-interactive response: #{e.message}"
    end

    def decode(value, field)
      return nil if value.nil?

      Base64.strict_decode64(value)
    rescue ArgumentError => e
      raise ResponseError, "could not Base64-decode response #{field}: #{e.message}"
    end
  end
end

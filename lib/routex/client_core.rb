# frozen_string_literal: true

require "base64"
require "securerandom"
require_relative "errors"
require_relative "settlement"
require_relative "ticket"

module Routex
  # Sealed-HTTP plumbing shared by the service clients. Port of RoutexClientCore.kt.
  #
  # Holds one Settlement (and one ChaChaBox keypair) per ticket id.
  class ClientCore
    MEDIA_TYPE = "application/vnd.yaxi.v5"
    HEADER_CLIENT_VERSION = "yaxi-client-version"
    HEADER_ACCEPT = "accept"
    HEADER_USER_AGENT = "user-agent"
    HEADER_TICKET_ID = "yaxi-ticket-id"
    HEADER_TICKET = "yaxi-ticket"
    HEADER_SESSION_ID = "yaxi-session-id"
    HEADER_REDIRECT_URI = "yaxi-redirect-uri"
    HEADER_TRACE_ID = "yaxi-trace-id"

    attr_reader :trace_id
    attr_accessor :redirect_uri

    def initialize(&settlement_factory)
      @settlement_factory = settlement_factory
      @settlements = {}
      @mutex = Mutex.new
      @trace_id = nil
    end

    def system_version_for(ticket_id) = @settlements[ticket_id]&.system_version

    # A ticket-less call (public search) still needs a ticket id for routing.
    def request(ticket:, path:, body: nil)
      ticket_id = ticket ? ticket.id : SecureRandom.uuid
      settlement = settlement_for(ticket_id)
      settled = settlement.settle(settlement_headers(ticket_id))

      headers = {
        HEADER_USER_AGENT => user_agent,
        HEADER_CLIENT_VERSION => client_version,
        HEADER_TICKET_ID => ticket_id,
        HEADER_SESSION_ID => settled.session_id,
        HEADER_ACCEPT => MEDIA_TYPE
      }
      headers[HEADER_TICKET] = Base64.strict_encode64(seal(settlement, ticket.raw)) if ticket
      headers[HEADER_REDIRECT_URI] = @redirect_uri if @redirect_uri
      headers["content-type"] = "application/json" if body

      response = settlement.transport.execute(
        method: body ? :post : :get,
        url: join_url(settlement.base_url, path),
        headers: headers,
        body: body ? seal(settlement, body) : nil
      )

      capture_trace_id(settlement, response)
      plain = unseal_best_effort(settlement, response.body, fallback: response.status >= 400)
      raise ErrorDispatcher.dispatch(response.status, plain) if response.status >= 400

      plain
    end

    def seal_payload(ticket_id, plaintext)
      settlement = settlement_for(ticket_id)
      settlement.settle(settlement_headers(ticket_id))
      seal(settlement, plaintext)
    end

    private

    def settlement_for(ticket_id)
      @mutex.synchronize { @settlements[ticket_id] ||= @settlement_factory.call }
    end

    def settlement_headers(ticket_id)
      { HEADER_USER_AGENT => user_agent, HEADER_CLIENT_VERSION => client_version, HEADER_TICKET_ID => ticket_id }
    end

    def user_agent = "RoutexClient/#{Routex::VERSION} (Ruby)"
    def client_version = "ruby/#{Routex::VERSION}"

    def seal(settlement, plaintext)
      settlement.seal(plaintext)
    rescue StandardError => e
      raise SealingError, "ChaChaBox seal failed: #{e.message}"
    end

    def capture_trace_id(settlement, response)
      header = response.headers[HEADER_TRACE_ID] || response.headers[HEADER_TRACE_ID.downcase]
      return unless header

      @trace_id = settlement.unseal(Base64.strict_decode64(header))
    rescue ArgumentError, ChaChaBox::DecryptError
      nil
    end

    # An error body may not be sealed (it can come from a proxy in front of the
    # TEE), so on a >= 400 status fall back to the raw bytes.
    def unseal_best_effort(settlement, body, fallback:)
      return body if body.empty?

      settlement.unseal(body)
    rescue StandardError => e
      raise UnsealingError, "response unseal failed: #{e.message}" unless fallback

      body
    end

    def join_url(base, path) = "#{base.to_s.chomp("/")}/#{path.sub(%r{\A/}, "")}"
  end
end

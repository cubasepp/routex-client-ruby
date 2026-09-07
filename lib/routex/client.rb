# frozen_string_literal: true

require "base64"
require "json"
require_relative "client_core"
require_relative "response"
require_relative "settlement"
require_relative "transport"
require_relative "version"

module Routex
  # Client for the interactive Open Banking services.
  #
  # A service call returns either a Result or an interrupt. Resolve interrupts
  # with respond_*/confirm_* and repeat until #result? is true:
  #
  #   response = client.accounts(ticket, credentials: credentials, fields: %w[iban])
  #   until response.result?
  #     response =
  #       case response
  #       when Routex::Dialog then
  #         if response.confirmation?
  #           client.confirm_accounts(ticket, response.input_context)
  #         else
  #           client.respond_accounts(ticket, response.input_context, answer)
  #         end
  #       when Routex::Redirect then
  #         visit(response.url)
  #         client.confirm_accounts(ticket, response.context)
  #       when Routex::RedirectHandle then
  #         url = client.register_redirect_uri(ticket, response.handle, "myapp://cb")
  #         visit(url)
  #         client.confirm_accounts(ticket, response.context)
  #       end
  #   end
  class Client
    PRODUCTION_URL = "https://api.yaxi.tech"
    INTEGRATION_URL = "https://integration.yaxi.tech"

    SERVICE_PATHS = {
      accounts: "accounts",
      balances: "balances",
      transactions: "transactions",
      transfer: "transfer",
      collect_payment: "collect-payment"
    }.freeze

    module PaymentProduct
      ALL = %w[
        SepaCreditTransfer SepaInstantCreditTransfer DefaultSepaCreditTransfer
        CrossBorderCreditTransfer DomesticCreditTransfer DomesticInstantCreditTransfer
      ].freeze
    end

    module ChargeBearer
      BORNE_BY_DEBTOR = "DEBT"
      BORNE_BY_CREDITOR = "CRED"
      SHARED = "SHAR"
      FOLLOWING_SERVICE_LEVEL = "SLEV"
    end

    attr_reader :core

    # Pass `core:` to supply your own ClientCore -- useful for tests and for
    # routing through an existing connection pool.
    def initialize(base_url: PRODUCTION_URL, transport: Transport.new,
                   requirements: Requirements::DEFAULT,
                   signing_keys: YaxiSystemVersionKeys::DEFAULT,
                   core: nil)
      @core = core || ClientCore.new do
        Settlement.new(base_url: base_url, transport: transport,
                       requirements: requirements, signing_keys: signing_keys)
      end
    end

    def redirect_uri=(uri)
      @core.redirect_uri = uri
    end

    def trace_id = @core.trace_id
    def system_version_for(ticket_id) = @core.system_version_for(ticket_id)

    SERVICE_PATHS.each do |name, path|
      # Answer a Dialog that asked for input (a TAN, a selected option's key).
      define_method(:"respond_#{name}") do |ticket, context, response|
        call(ticket, "#{path}/response",
             { context: Base64.strict_encode64(context), response: response })
      end

      # Confirm a decoupled SCA, a completed redirect, or a poll.
      define_method(:"confirm_#{name}") do |ticket, context|
        call(ticket, "#{path}/confirmation", { context: Base64.strict_encode64(context) })
      end
    end

    def accounts(ticket, credentials:, session: nil, recurring_consents: false,
                 fields: nil, filter: nil)
      call(ticket, "accounts/service",
           service_body(credentials, session, recurring_consents,
                        fields: fields || [], filter: filter))
    end

    def balances(ticket, credentials:, accounts:, session: nil, recurring_consents: false)
      call(ticket, "balances/service",
           service_body(credentials, session, recurring_consents, accounts: accounts))
    end

    def transactions(ticket, credentials:, session: nil, recurring_consents: false)
      call(ticket, "transactions/service",
           service_body(credentials, session, recurring_consents))
    end

    def collect_payment(ticket, credentials:, account: nil, session: nil, recurring_consents: false)
      call(ticket, "collect-payment/service",
           service_body(credentials, session, recurring_consents, account: account))
    end

    def transfer(ticket, credentials:, details:, product: nil, debtor_account: nil,
                 debtor_name: nil, requested_execution_date: nil,
                 session: nil, recurring_consents: false)
      call(ticket, "transfer/service",
           service_body(credentials, session, recurring_consents,
                        product: product,
                        debtorAccount: debtor_account,
                        debtorName: debtor_name,
                        requestedExecutionDate: format_date(requested_execution_date),
                        details: details))
    end

    # Search the connection directory. Works without a ticket, in which case a
    # random ticket id is sent so the request can still be routed.
    def search(ticket = nil, filters: [], iban_detection: false, limit: nil, details: nil)
      body = compact(ibanDetection: iban_detection, filters: filters, limit: limit, details: details)
      JSON.parse(@core.request(ticket: ticket, path: "search", body: JSON.generate(body)))
    end

    def info(ticket, connection_id)
      JSON.parse(@core.request(ticket: ticket, path: "info/#{connection_id}"))
    end

    # Exchange a RedirectHandle for the URL to send the user to.
    def register_redirect_uri(ticket, handle, redirect_uri)
      body = JSON.generate(handle: handle, redirectUri: redirect_uri)
      json = JSON.parse(@core.request(ticket: ticket, path: "redirects", body: body))
      json["redirectUrl"] or raise ResponseError, "expected redirectUrl in response"
    end

    def trace(ticket, trace_id)
      sealed = @core.seal_payload(ticket.id, trace_id)
      path = "traces/#{Base64.urlsafe_encode64(sealed, padding: false)}"
      JSON.parse(@core.request(ticket: ticket, path: path))
    end

    private

    def call(ticket, path, body)
      Response.parse(@core.request(ticket: ticket, path: path, body: JSON.generate(body)))
    end

    # The envelope every service call shares. `connectionData`, `session` and
    # `recurringConsents` are always present -- explicit null rather than an
    # omitted key -- which is what the services expect.
    def service_body(credentials, session, recurring_consents, **extra)
      credentials = normalize_credentials(credentials)
      {
        credentials: credentials,
        session: session && Base64.strict_encode64(session),
        recurringConsents: recurring_consents || false
      }.merge(compact(extra))
    end

    def normalize_credentials(credentials)
      credentials = credentials.transform_keys(&:to_sym)
      connection_data = credentials[:connection_data] || credentials[:connectionData]
      body = {
        connectionId: credentials[:connection_id] || credentials[:connectionId],
        connectionData: connection_data && Base64.strict_encode64(connection_data)
      }
      body[:userId] = credentials[:user_id] || credentials[:userId] if credentials[:user_id] || credentials[:userId]
      body[:password] = credentials[:password] if credentials[:password]
      body
    end

    def format_date(value)
      return nil if value.nil?
      return value if value.is_a?(String)

      value.strftime("%Y-%m-%d")
    end

    def compact(hash) = hash.reject { |_, value| value.nil? }
  end
end

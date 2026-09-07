# frozen_string_literal: true

require "json"
require "uri"
require_relative "client_core"
require_relative "response"
require_relative "settlement"
require_relative "transport"
require_relative "version"

module Routex
  # Interactive Open Banking client. Port of RoutexClient.kt.
  #
  # Every service call returns a ServiceResponse; when it is an interrupt
  # (Dialog / Redirect / RedirectHandle) resolve it with the matching
  # respond_* / confirm_* call and repeat until #result? is true.
  class Client
    PRODUCTION_URL = "https://api.yaxi.tech"
    INTEGRATION_URL = "https://integration.yaxi.tech"

    SERVICES = {
      accounts: "accounts",
      balances: "balances",
      transactions: "transactions",
      transfer: "transfer",
      collect_payment: "collect-payment"
    }.freeze

    attr_reader :core

    def initialize(base_url: PRODUCTION_URL, transport: Transport.new,
                   requirements: Requirements::DEFAULT,
                   signing_keys: YaxiSystemVersionKeys::DEFAULT)
      @core = ClientCore.new do
        Settlement.new(base_url: base_url, transport: transport,
                       requirements: requirements, signing_keys: signing_keys)
      end
    end

    def redirect_uri=(uri)
      @core.redirect_uri = uri
    end

    def trace_id = @core.trace_id

    SERVICES.each do |name, path|
      # e.g. #accounts(ticket, credentials:, fields: [...])
      define_method(name) do |ticket, **params|
        call(ticket, "#{path}/service", params)
      end

      # Answer a Dialog interrupt that asked for input.
      define_method(:"respond_#{name}") do |ticket, context, user_input|
        call(ticket, "#{path}/response", { context: context, input: user_input })
      end

      # Confirm a decoupled SCA / redirect interrupt and resume.
      define_method(:"confirm_#{name}") do |ticket, context|
        call(ticket, "#{path}/context", { context: context })
      end
    end

    def search(ticket, filters: [], iban_detection: false, limit: 20)
      call(ticket, "search", { filters: filters, ibanDetection: iban_detection, limit: limit })
    end

    def register_redirect_uri(ticket, handle, uri)
      body = JSON.generate(handle: handle, redirectUri: uri)
      response = JSON.parse(@core.request(ticket: ticket, path: "redirects/handle", body: body))
      response.fetch("url")
    end

    def trace(ticket, trace_id)
      JSON.parse(@core.request(ticket: ticket, path: "traces/#{URI.encode_www_form_component(trace_id)}"))
    end

    def system_version_for(ticket_id) = @core.system_version_for(ticket_id)

    private

    def call(ticket, path, params)
      body = JSON.generate(compact(params))
      ServiceResponse.parse(@core.request(ticket: ticket, path: path, body: body))
    end

    def compact(params)
      params.reject { |_, v| v.nil? }
            .transform_keys { |k| camelize(k) }
    end

    def camelize(key)
      head, *rest = key.to_s.split("_")
      (head + rest.map(&:capitalize).join).to_sym
    end
  end
end

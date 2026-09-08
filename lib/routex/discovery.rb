# frozen_string_literal: true

require "base64"
require "json"

module Routex
  # Endpoints both clients expose: connection lookup and the trace read-back.
  # Mirrors what the Lua client puts on Core.
  module Discovery
    # Search the connection directory. Works without a ticket, in which case the
    # core sends a random ticket id so the request can still be routed.
    def search(ticket = nil, filters: [], iban_detection: false, limit: nil, details: nil)
      body = { ibanDetection: iban_detection, filters: filters, limit: limit, details: details }
                .reject { |_, value| value.nil? }
      JSON.parse(@core.request(ticket: ticket, path: "search", body: JSON.generate(body)))
    end

    def info(ticket, connection_id)
      JSON.parse(@core.request(ticket: ticket, path: "info/#{connection_id}"))
    end

    def trace(ticket, trace_id)
      sealed = @core.seal_payload(ticket.id, trace_id)
      path = "traces/#{Base64.urlsafe_encode64(sealed, padding: false)}"
      JSON.parse(@core.request(ticket: ticket, path: path))
    end

    def trace_id = @core.trace_id
    def system_version_for(ticket_id) = @core.system_version_for(ticket_id)
  end
end

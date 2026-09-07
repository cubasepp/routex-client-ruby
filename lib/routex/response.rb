# frozen_string_literal: true

require "json"
require_relative "errors"

module Routex
  # A service call answers with exactly one of four externally tagged variants:
  # {"Dialog": ...}, {"Redirect": ...}, {"RedirectHandle": ...}, {"Result": ...}.
  #
  # Modelled as a thin wrapper over the decoded JSON rather than a full class
  # hierarchy -- see PORTING.md on why the models module stays this light.
  class ServiceResponse
    VARIANTS = %w[Dialog Redirect RedirectHandle Result].freeze

    attr_reader :variant, :payload

    def self.parse(bytes)
      decoded = JSON.parse(bytes)
      unless decoded.is_a?(Hash) && decoded.size == 1
        raise Error, "expected a single-key externally tagged object, got #{decoded.class}"
      end

      variant, payload = decoded.first
      raise Error, "unknown response variant #{variant.inspect}" unless VARIANTS.include?(variant)

      new(variant, payload)
    rescue JSON::ParserError => e
      raise Error, "malformed service response: #{e.message}"
    end

    def initialize(variant, payload)
      @variant = variant
      @payload = payload
    end

    def dialog? = @variant == "Dialog"
    def redirect? = @variant == "Redirect"
    def redirect_handle? = @variant == "RedirectHandle"
    def result? = @variant == "Result"

    # Interrupts carry a context token that the matching confirm/respond call
    # must echo back.
    def context = @payload["context"] || @payload.dig(@variant.sub(/\A./, &:downcase), "context")

    # Present on Result: the authenticated payload as a signed JWT. Verify the
    # signature in a trusted environment before acting on it.
    def jwt = @payload.dig("authenticated", "jwt")
    def session = @payload["session"]
    def connection_data = @payload["connectionData"]

    def dialog_input
      return nil unless dialog?

      @payload.dig("dialog", "input")
    end

    def to_h = { @variant => @payload }
  end
end

# frozen_string_literal: true

module Routex
  class Error < StandardError; end

  class TransportError < Error; end
  class SealingError < Error; end
  class UnsealingError < Error; end

  module ChaChaBox
    class DecryptError < Routex::Error; end
  end

  # Attestation and key-settlement failures. Every one of these means the client
  # could not prove it is talking to the expected TEE, and must not proceed.
  class AttestationError < Error; end
  class ReportDecodeError < AttestationError; end
  class ReportVerificationError < AttestationError; end
  class VcekChainError < AttestationError; end
  class SystemVersionError < AttestationError; end

  class KeySettlementError < AttestationError; end
  class MalformedSettlementResponse < KeySettlementError; end
  class ChachaBoxBindingMismatch < KeySettlementError; end
  class MeasurementMismatch < KeySettlementError; end
  class NotSettledError < KeySettlementError; end

  # Typed service errors, mirroring the externally tagged error envelope the
  # services return. See https://docs.yaxi.tech/errors.html.
  class ServiceError < Error
    attr_reader :code, :user_message, :status, :body

    def initialize(message = nil, code: nil, user_message: nil, status: nil, body: nil)
      super(message || user_message || self.class.name.split("::").last)
      @code = code
      @user_message = user_message
      @status = status
      @body = body
    end
  end

  class UnexpectedError < ServiceError; end
  class CanceledError < ServiceError; end
  class InvalidCredentialsError < ServiceError; end
  class ServiceBlockedError < ServiceError; end
  class UnauthorizedError < ServiceError; end
  class AccessExceededError < ServiceError; end
  class PeriodOutOfBoundsError < ServiceError; end
  class UnsupportedProductError < ServiceError; end
  class PaymentFailedError < ServiceError; end
  class UnexpectedValueError < ServiceError; end
  class TicketError < ServiceError; end
  class ProviderError < ServiceError; end
  class InterruptError < ServiceError; end
  class NotFoundError < ServiceError; end
  class ResponseError < ServiceError; end

  # Maps the single-key error envelope onto the classes above.
  module ErrorDispatcher
    # variant => [class, code key, message key]
    VARIANTS = {
      "UnexpectedError" => [UnexpectedError, nil, "userMessage"],
      "Canceled" => [CanceledError, nil, nil],
      "InvalidCredentials" => [InvalidCredentialsError, nil, "userMessage"],
      "ServiceBlocked" => [ServiceBlockedError, "code", "userMessage"],
      "Unauthorized" => [UnauthorizedError, nil, "userMessage"],
      "AccessExceeded" => [AccessExceededError, nil, "userMessage"],
      "PeriodOutOfBounds" => [PeriodOutOfBoundsError, nil, "userMessage"],
      "UnsupportedProduct" => [UnsupportedProductError, "reason", "userMessage"],
      "PaymentFailed" => [PaymentFailedError, "code", "userMessage"],
      "UnexpectedValue" => [UnexpectedValueError, nil, "error"],
      "TicketError" => [TicketError, "code", "error"],
      "ProviderError" => [ProviderError, "code", "userMessage"],
      "InterruptError" => [InterruptError, nil, nil]
    }.freeze

    # A TicketError is almost always a local mistake, so say what to check.
    TICKET_HINTS = {
      "UnknownKey" => "Make sure your YAXI API key exists in your environment and is Base64 encoded.",
      "InvalidSignature" => "Make sure the ticket JWT is signed with HMAC-SHA256.",
      'Invalid "yaxi-ticket" header' => "Make sure the ticket matches the service being called."
    }.freeze

    module_function

    def dispatch(status, body)
      decoded = begin
        JSON.parse(body)
      rescue JSON::ParserError, TypeError
        nil
      end

      return NotFoundError.new(status: status, body: body) if status == 404 && !error_variant(decoded)

      variant, payload = error_variant(decoded)
      unless variant
        return ResponseError.new("service returned HTTP #{status}", status: status, body: body)
      end

      build(variant, payload, status, body)
    end

    def error_variant(decoded)
      return nil unless decoded.is_a?(Hash)

      decoded.find { |key, _| VARIANTS.key?(key) }
    end

    def build(variant, payload, status, body)
      klass, code_key, message_key = VARIANTS.fetch(variant)
      payload = {} unless payload.is_a?(Hash)
      code = code_key && payload[code_key]
      message = message_key && payload[message_key]
      message = "#{message}. #{hint(variant, code, message)}" if hint(variant, code, message)

      klass.new(message, code: code, user_message: message_key && payload[message_key],
                         status: status, body: body)
    end

    def hint(variant, code, message)
      return nil unless variant == "TicketError"

      TICKET_HINTS[message] || TICKET_HINTS[code]
    end
  end
end

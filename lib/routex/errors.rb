# frozen_string_literal: true

module Routex
  class Error < StandardError; end

  # Raised when the server answers a service call with a typed error body.
  class ServerError < Error
    attr_reader :status, :code, :body

    def initialize(message, status: nil, code: nil, body: nil)
      super(message)
      @status = status
      @code = code
      @body = body
    end
  end

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
end

# frozen_string_literal: true

require "base64"
require "json"
require_relative "chacha_box"
require_relative "report_verifier"
require_relative "system_version"
require_relative "yaxi_system_version_keys"

module Routex
  # One TEE-attested key-settlement session. Port of Settlement.kt + KeySettlement.kt.
  #
  # A settlement is bound to one ticket id: the YAXI gateway routes tickets to
  # specific service instances, so a shared session would land later requests at
  # an instance that has no record of it.
  class Settlement
    MEDIA_TYPE = "application/vnd.yaxi.v5"
    DEFAULT_PATH = "key-settlement"
    REPORT_BINDING_BYTES = 32

    Result = Struct.new(:server_public_key, :session_id, :system_version, keyword_init: true)

    attr_reader :base_url, :transport

    def initialize(base_url:, transport:, signing_keys: YaxiSystemVersionKeys::DEFAULT,
                   requirements: Requirements::DEFAULT, path: DEFAULT_PATH,
                   client_keys: ChaChaBox.generate_keys)
      @base_url = base_url
      @transport = transport
      @signing_keys = signing_keys
      @requirements = requirements
      @path = path
      @client_keys = client_keys
      @mutex = Mutex.new
      @settled = nil
    end

    def settled? = !@settled.nil?
    def session_id = @settled&.session_id
    def system_version = @settled&.system_version
    def client_public_key = @client_keys.public

    # Idempotent and thread-safe: only the first caller performs the handshake.
    def settle(extra_headers = {})
      @mutex.synchronize do
        next @settled if @settled

        response = @transport.execute(
          method: :post,
          url: join_url(@base_url, @path),
          headers: { "Accept" => MEDIA_TYPE, "Content-Type" => "application/json" }.merge(extra_headers),
          body: JSON.generate(publicKey: Base64.strict_encode64(@client_keys.public))
        )
        raise ServerError.new("key settlement failed", status: response.status, body: response.body) if
          response.status >= 400

        @settled = verify(response.body)
      end
    end

    def seal(plaintext)
      settled = @settled or raise NotSettledError, "settle must succeed before sealing"
      ChaChaBox.seal(settled.server_public_key, plaintext)
    end

    # Available pre-settle: the recipient-side key material exists from construction.
    def unseal(ciphertext) = ChaChaBox.unseal(@client_keys, ciphertext)

    private

    # Verification order matches the Kotlin client exactly: attestation, then the
    # ChaChaBox binding, then the system-version signature, then the measurement
    # match, and only then the decrypt.
    def verify(response_bytes)
      body = parse_response(response_bytes)
      report_bytes = decode_base64(body, "attestationReport")
      chacha_box = decode_base64(body, "chachaBox")

      report, = ReportVerifier.verify_bytes(
        report_bytes, body.fetch("vcek"), requirements: @requirements
      )

      unless Crypto.secure_compare(Crypto.sha256(chacha_box),
                                   report.report_data.byteslice(0, REPORT_BINDING_BYTES))
        raise ChachaBoxBindingMismatch, "chachaBox is not bound to the attestation report"
      end

      entry = SystemVersion.from_json(body.fetch("systemVersion"))
      measurement = SystemVersion.verify(entry, @signing_keys)

      unless Crypto.secure_compare(measurement, report.measurement)
        raise MeasurementMismatch, "system-version measurement does not match the attested launch measurement"
      end

      payload = JSON.parse(ChaChaBox.unseal(@client_keys, chacha_box))
      Result.new(
        server_public_key: Base64.strict_decode64(payload.fetch("publicKey")),
        session_id: payload.fetch("sessionId"),
        system_version: entry
      )
    rescue KeyError, JSON::ParserError => e
      raise MalformedSettlementResponse, "malformed settlement response: #{e.message}"
    end

    def parse_response(bytes)
      JSON.parse(bytes)
    rescue JSON::ParserError => e
      raise MalformedSettlementResponse, "failed to decode settlement response JSON: #{e.message}"
    end

    def decode_base64(body, field)
      Base64.strict_decode64(body.fetch(field))
    rescue ArgumentError => e
      raise MalformedSettlementResponse, "#{field} is not valid base64: #{e.message}"
    end

    def join_url(base, path)
      "#{base.to_s.chomp("/")}/#{path.sub(%r{\A/}, "")}"
    end
  end
end

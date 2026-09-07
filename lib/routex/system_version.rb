# frozen_string_literal: true

require "base64"
require_relative "crypto"
require_relative "errors"

module Routex
  # Verifies the Ed25519-signed system-version entry and returns its launch
  # measurement. Port of SystemVersion.kt.
  module SystemVersion
    Entry = Struct.new(:kind, :generation, :raw_created_at, :ref, :launch_measurement,
                       :signature_key_id, :signature_value, :raw, keyword_init: true)

    module_function

    def from_json(hash)
      signature = hash.fetch("signature")
      Entry.new(
        kind: hash.fetch("kind"),
        generation: hash.fetch("generation"),
        raw_created_at: hash.fetch("createdAt"),
        ref: hash.fetch("ref"),
        launch_measurement: Base64.strict_decode64(hash.fetch("launchMeasurement")),
        signature_key_id: signature.fetch("keyId"),
        signature_value: signature.fetch("value"),
        raw: hash
      )
    rescue KeyError => e
      raise SystemVersionError, "malformed system-version entry: #{e.message}"
    end

    def verify(entry, verifying_keys)
      key = verifying_keys[entry.signature_key_id]
      raise SystemVersionError, "unknown system-version signing key id: #{entry.signature_key_id}" unless key

      begin
        signature = Base64.strict_decode64(entry.signature_value)
      rescue ArgumentError => e
        raise SystemVersionError, "signature value is not valid base64: #{e.message}"
      end

      unless Crypto.ed25519_verify(key, signed_message(entry), signature)
        raise SystemVersionError, "system-version signature is invalid"
      end

      entry.launch_measurement
    end

    # The signed message concatenates the entry's scalar fields, with the RFC-3339
    # "Z" suffix normalised to "+00:00", followed by the raw measurement bytes.
    def signed_message(entry)
      created_at = entry.raw_created_at.end_with?("Z") ? "#{entry.raw_created_at[0..-2]}+00:00" : entry.raw_created_at
      "#{entry.kind}#{entry.generation}#{created_at}#{entry.ref}".b + entry.launch_measurement
    end
  end
end

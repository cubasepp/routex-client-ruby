# frozen_string_literal: true

require "openssl"
require_relative "errors"

module Routex
  # X.509 wrapper exposing exactly what the VCEK chain validator needs, including
  # the AMD-specific extensions from AMD doc 57230 rev. 1.00 section 3.1.
  class VcekCertificate
    OIDS = {
      product_name: "1.3.6.1.4.1.3704.1.2",
      bl_spl: "1.3.6.1.4.1.3704.1.3.1",
      tee_spl: "1.3.6.1.4.1.3704.1.3.2",
      snp_spl: "1.3.6.1.4.1.3704.1.3.3",
      ucode_spl: "1.3.6.1.4.1.3704.1.3.8",
      fmc_spl: "1.3.6.1.4.1.3704.1.3.9"
    }.freeze

    Tcb = Struct.new(:bootloader, :tee, :snp, :microcode, :fmc, keyword_init: true)

    attr_reader :x509

    def self.parse_chain(pem)
      blocks = pem.to_s.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
      raise VcekChainError, "no PEM certificate found" if blocks.empty?

      blocks.map do |block|
        new(OpenSSL::X509::Certificate.new(block))
      rescue OpenSSL::X509::CertificateError => e
        raise VcekChainError, "failed to parse PEM certificate: #{e.message}"
      end
    end

    def initialize(x509)
      @x509 = x509
    end

    def subject_der = @x509.subject.to_der
    def issuer_der = @x509.issuer.to_der
    def valid_from = @x509.not_before
    def valid_until = @x509.not_after

    def subject_common_name
      @x509.subject.to_a.find { |name, _, _| name == "CN" }&.at(1)
    end

    def verify_signature_by(issuer)
      return if @x509.verify(issuer.x509.public_key)

      raise VcekChainError, "certificate signature invalid"
    rescue OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError => e
      raise VcekChainError, "certificate signature verification failed: #{e.message}"
    end

    def certificate_authority?
      basic_constraints.fetch(:ca, false)
    end

    # nil when unconstrained or absent; only meaningful for a CA.
    def max_intermediate_certificates
      basic_constraints[:path_len]
    end

    def allows_certificate_signing?
      ext = extension("keyUsage")
      return true unless ext

      ext.value.split(",").map(&:strip).include?("Certificate Sign")
    end

    def product_name
      extension_as_ia5_string(OIDS[:product_name]) ||
        raise(VcekChainError, "required extension #{OIDS[:product_name]} is not present")
    end

    def tcb
      Tcb.new(
        bootloader: require_int(OIDS[:bl_spl]),
        tee: require_int(OIDS[:tee_spl]),
        snp: require_int(OIDS[:snp_spl]),
        microcode: require_int(OIDS[:ucode_spl]),
        fmc: extension_as_integer(OIDS[:fmc_spl])
      )
    end

    def verify_ecdsa_p384_sha384(message, r_big_endian, s_big_endian)
      der = Crypto.ecdsa_raw_to_der(r_big_endian, s_big_endian)
      @x509.public_key.verify(OpenSSL::Digest.new("SHA384"), der, message)
    rescue OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error
      false
    end

    def extension_as_ia5_string(oid)
      inner = extension_inner(oid)
      return nil unless inner

      value = OpenSSL::ASN1.decode(inner)
      unless value.tag == OpenSSL::ASN1::IA5STRING
        raise VcekChainError, "extension #{oid} is not a valid IA5String"
      end

      value.value
    rescue OpenSSL::ASN1::ASN1Error => e
      raise VcekChainError, "extension #{oid} is not a valid IA5String: #{e.message}"
    end

    def extension_as_integer(oid)
      inner = extension_inner(oid)
      return nil unless inner

      value = OpenSSL::ASN1.decode(inner)
      raise VcekChainError, "extension #{oid} is not a valid INTEGER" unless value.tag == OpenSSL::ASN1::INTEGER

      int = value.value.to_i
      raise VcekChainError, "extension #{oid} INTEGER out of range (#{int})" if int.negative? || int > 0x7FFF_FFFF

      int
    rescue OpenSSL::ASN1::ASN1Error => e
      raise VcekChainError, "extension #{oid} is not a valid INTEGER: #{e.message}"
    end

    private

    def require_int(oid)
      extension_as_integer(oid) || raise(VcekChainError, "required extension #{oid} is not present")
    end

    def extension(oid)
      @x509.extensions.find { |e| e.oid == oid }
    end

    # OpenSSL hands back the extension DER already unwrapped from its outer OCTET
    # STRING, unlike the JCA getExtensionValue the Kotlin client has to strip.
    def extension_inner(oid)
      extension(oid)&.value_der
    end

    def basic_constraints
      @basic_constraints ||= begin
        ext = extension("basicConstraints")
        if ext.nil?
          { ca: false, path_len: nil }
        else
          parts = ext.value.split(",").map(&:strip)
          path = parts.find { |p| p.start_with?("pathlen:") }
          { ca: parts.include?("CA:TRUE"), path_len: path&.split(":")&.last&.to_i }
        end
      end
    end
  end
end

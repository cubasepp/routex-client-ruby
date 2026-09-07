# frozen_string_literal: true

require_relative "attestation_report"
require_relative "requirements"
require_relative "vcek_chain"

module Routex
  # Enforces the platform gates on a parsed attestation report. Port of ReportVerifier.kt.
  #
  # Every raise here means the client could not establish that it is talking to a
  # TEE in the expected state. There is no "warn and continue" path by design.
  module ReportVerifier
    module_function

    def verify_bytes(report_bytes, vcek_chain_pem, requirements: Requirements::DEFAULT,
                     roots: AmdRootStore.certificates, now: Time.now)
      chain = VcekChain.verify(vcek_chain_pem, roots: roots, now: now)
      report = AttestationReport.parse(report_bytes)
      verify(report, chain, requirements)
      [report, chain]
    end

    def verify(report, chain, requirements = Requirements::DEFAULT)
      unless report.signature_algo == AttestationReport::ECDSA_P384_SHA384
        raise ReportVerificationError, "unsupported attestation signature algorithm: #{report.signature_algo}"
      end

      verify_signature_padding(report)
      verify_report_signature(report, chain)

      verify_platform_gates(report, chain, requirements) if requirements.pinned?

      verify_tcb_against_vcek(report.reported_tcb, chain.vcek_tcb)
    end

    def verify_platform_gates(report, chain, requirements)
      raise ReportVerificationError, "alias check was not completed" unless report.platform_info[:alias_check_complete]
      raise ReportVerificationError, "debug mode is enabled in guest policy" if report.policy[:debug_allowed]
      raise ReportVerificationError, "guest policy allows a migration agent" if report.policy[:migrate_ma_allowed]
      raise ReportVerificationError, "unexpected VMPL #{report.vmpl} (must be <= 3)" if report.vmpl > 3
      unless report.key_info[:signing_key_kind] == :vcek
        raise ReportVerificationError, "report is not signed by a VCEK (#{report.key_info[:signing_key_kind]})"
      end

      product = requirements.for_family(chain.family)

      if report.committed_version.packed < product.min_committed_version.packed
        raise ReportVerificationError,
              "committed firmware too low: required=#{product.min_committed_version} " \
              "actual=#{report.committed_version}"
      end

      if report.committed_tcb.snp < product.min_committed_tcb_snp
        raise ReportVerificationError,
              "committed SNP TCB too low: required=#{product.min_committed_tcb_snp} " \
              "actual=#{report.committed_tcb.snp}"
      end

      verify_mit_vector("current", product.min_mit_vector, report.current_mit_vector)
      verify_mit_vector("launch", product.min_mit_vector, report.launch_mit_vector)
      verify_microcode(report, chain, requirements, product)
    end

    # Pre-v3 reports carry no cpuid_mod_id/cpuid_step, so they fall back to the
    # per-family floor. That floor is set to the strictest per-stepping entry, so
    # claiming version < 3 cannot be used to reach a weaker microcode requirement.
    def verify_microcode(report, chain, requirements, product)
      minimum =
        if report.cpuid_mod_id && report.cpuid_step
          requirements.min_microcode(chain.family, report.cpuid_mod_id, report.cpuid_step) ||
            raise(ReportVerificationError,
                  "no microcode requirement for family=#{chain.family} " \
                  "model=#{report.cpuid_mod_id} step=#{report.cpuid_step}")
        else
          product.fallback_microcode
        end

      return unless report.committed_tcb.microcode < minimum

      raise ReportVerificationError,
            "committed microcode too low: required=#{minimum} actual=#{report.committed_tcb.microcode}"
    end

    # A required mask of 0 disables the check. Absence of the field on a pre-v5
    # report is a failure when the bulletin requires bits: only the signed
    # LAUNCH_MIT_VECTOR / CURRENT_MIT_VECTOR prove SNP_VERIFY_MITIGATION ran.
    def verify_mit_vector(field, required, actual)
      return if required.zero?

      if actual.nil?
        raise ReportVerificationError,
              "#{field} mitigation vector absent, required=0x#{required.to_s(16)}"
      end
      return if (actual & required) == required

      raise ReportVerificationError,
            "#{field} mitigation vector below required bits: " \
            "actual=0x#{actual.to_s(16)} required=0x#{required.to_s(16)}"
    end

    def verify_signature_padding(report)
      raw = report.signature.raw
      slot = AttestationReport::ECDSA_SCALAR_SLOT_LEN
      scalar = AttestationReport::ECDSA_SCALAR_LEN
      r_pad = raw.byteslice(scalar, slot - scalar)
      s_pad = raw.byteslice(slot + scalar, slot - scalar)
      return if r_pad.each_byte.all?(&:zero?) && s_pad.each_byte.all?(&:zero?)

      raise ReportVerificationError, "unexpected non-zero bits in ECDSA scalar slot"
    end

    def verify_report_signature(report, chain)
      valid = chain.leaf.verify_ecdsa_p384_sha384(
        report.signed_bytes,
        report.signature.r_little_endian.reverse,
        report.signature.s_little_endian.reverse
      )
      raise ReportVerificationError, "attestation report signature is invalid" unless valid
    end

    def verify_tcb_against_vcek(reported, vcek)
      %i[bootloader tee snp microcode fmc].each do |field|
        next if reported[field] == vcek[field]

        raise ReportVerificationError,
              "reported TCB does not match VCEK: #{field} expected=#{vcek[field]} actual=#{reported[field]}"
      end
    end
  end
end

# frozen_string_literal: true

require_relative "test_helper"

# End-to-end attestation verification against real AMD SEV-SNP material: complete
# VCEK chains and the attestation reports signed under their leaves. See
# test/fixtures/vcek/PROVENANCE.md.
#
# This is the test that proves the port actually verifies rather than merely
# parses -- it exercises the RSASSA-PSS chain, the AMD extension readers, the
# ECDSA P-384/SHA-384 report signature under a real VCEK public key, and the
# platform gates, in the same order the upstream clients apply them.
class AttestationVerificationTest < Minitest::Test
  def test_verifies_a_genuine_genoa_v5_report_end_to_end
    report, chain = Routex::ReportVerifier.verify_bytes(
      attestation_report_bytes("genoa_v5"), vcek_chain("genoa-v5")
    )

    assert_equal 5, report.version
    assert_equal :genoa, chain.family
    assert_equal "Genoa", chain.product_name
    assert_equal :vcek, report.key_info[:signing_key_kind]
  end

  def test_reported_tcb_matches_the_vcek_for_a_genuine_report
    report, chain = Routex::ReportVerifier.verify_bytes(
      attestation_report_bytes("genoa_v5"), vcek_chain("genoa-v5")
    )

    %i[bootloader tee snp microcode fmc].each do |field|
      assert_equal chain.vcek_tcb[field], report.reported_tcb[field], "TCB field #{field} diverged"
    end
  end

  # The reports below are genuine and their chains are valid; they are rejected
  # purely because the platform is below the pinned SB-3023 floors.
  {
    "genoa_v3" => "genoa",
    "milan" => "milan",
    "turin" => "turin"
  }.each do |report_name, chain_name|
    define_method(:"test_rejects_a_genuine_#{report_name}_report_below_the_pinned_requirements") do
      error = assert_raises(Routex::ReportVerificationError) do
        Routex::ReportVerifier.verify_bytes(attestation_report_bytes(report_name), vcek_chain(chain_name))
      end
      assert_match(/committed firmware too low/, error.message)
    end
  end

  def test_the_same_reports_pass_the_structural_checks_under_permissive
    { "genoa_v3" => "genoa", "milan" => "milan", "turin" => "turin" }.each do |report_name, chain_name|
      Routex::ReportVerifier.verify_bytes(
        attestation_report_bytes(report_name), vcek_chain(chain_name),
        requirements: Routex::Requirements::Permissive
      )
    end
  end

  def test_rejects_a_report_whose_signature_slot_was_overwritten
    bytes = attestation_report_bytes("genoa_v5").dup
    bytes[Routex::AttestationReport::SIGNATURE_OFFSET, Routex::AttestationReport::SIGNATURE_LENGTH] =
      "W" * Routex::AttestationReport::SIGNATURE_LENGTH

    error = assert_raises(Routex::ReportVerificationError) do
      Routex::ReportVerifier.verify_bytes(bytes, vcek_chain("genoa-v5"))
    end
    assert_match(/scalar slot/, error.message)
  end

  def test_rejects_a_report_with_a_flipped_signature_bit
    bytes = attestation_report_bytes("genoa_v5").dup
    offset = Routex::AttestationReport::SIGNATURE_OFFSET
    bytes.setbyte(offset, bytes.getbyte(offset) ^ 0x01)

    error = assert_raises(Routex::ReportVerificationError) do
      Routex::ReportVerifier.verify_bytes(bytes, vcek_chain("genoa-v5"))
    end
    assert_match(/signature is invalid/, error.message)
  end

  def test_rejects_a_report_whose_body_was_tampered_with
    bytes = attestation_report_bytes("genoa_v5").dup
    offset = Routex::AttestationReport::OFFSETS.fetch(:measurement)
    bytes.setbyte(offset, bytes.getbyte(offset) ^ 0xFF)

    assert_raises(Routex::ReportVerificationError) do
      Routex::ReportVerifier.verify_bytes(bytes, vcek_chain("genoa-v5"))
    end
  end

  def test_rejects_a_genuine_report_against_the_wrong_generation_chain
    assert_raises(Routex::AttestationError) do
      Routex::ReportVerifier.verify_bytes(attestation_report_bytes("genoa_v5"), vcek_chain("milan"))
    end
  end

  def test_rejects_a_chain_that_does_not_reach_a_trusted_root
    assert_raises(Routex::VcekChainError) do
      Routex::ReportVerifier.verify_bytes(
        attestation_report_bytes("genoa_v5"), vcek_chain("genoa-v5"), roots: []
      )
    end
  end

  def test_rejects_an_expired_chain
    assert_raises(Routex::VcekChainError) do
      Routex::ReportVerifier.verify_bytes(
        attestation_report_bytes("genoa_v5"), vcek_chain("genoa-v5"), now: Time.at(0)
      )
    end
  end
end

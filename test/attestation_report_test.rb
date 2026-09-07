# frozen_string_literal: true

require_relative "test_helper"

# The fixture is the Milan v2 report from the upstream Kotlin client's
# AttestationReportParserTest.
class AttestationReportTest < Minitest::Test
  OFF_VERSION = 0x000
  OFF_CPUID_FAM_ID = 0x188
  OFF_CHIP_ID = 0x1A0
  OFF_RESERVED_TAIL = 0x208
  OFF_SIGNATURE = 0x2A0

  def report = Routex::AttestationReport.parse(milan_v2_report_bytes)

  def test_parses_the_milan_v2_fixture
    r = report
    assert_equal 2, r.version
    assert_equal 0, r.vmpl
    assert_equal Routex::AttestationReport::ECDSA_P384_SHA384, r.signature_algo
    assert_equal :vcek, r.key_info[:signing_key_kind]
    refute r.policy[:debug_allowed]
    refute r.policy[:migrate_ma_allowed]
  end

  def test_uses_the_legacy_tcb_layout_for_milan
    tcb = report.reported_tcb
    assert_equal 0, tcb.fmc
    assert_equal 3, tcb.bootloader
    assert_equal 8, tcb.snp
    assert_equal 0x73, tcb.microcode
  end

  def test_exposes_fixed_width_fields
    r = report
    assert_equal 64, r.report_data.bytesize
    assert_equal 48, r.measurement.bytesize
    assert_equal 32, r.host_data.bytesize
    assert_equal 64, r.chip_id.bytesize
    assert_equal 48, r.signature.r_little_endian.bytesize
    assert_equal 48, r.signature.s_little_endian.bytesize
  end

  def test_signed_bytes_stop_at_the_signature
    assert_equal Routex::AttestationReport::SIGNATURE_OFFSET, report.signed_bytes.bytesize
  end

  def test_v2_report_has_no_mitigation_vectors
    assert_nil report.launch_mit_vector
    assert_nil report.current_mit_vector
  end

  def test_v2_report_has_no_cpuid_fields
    assert_nil report.cpuid_mod_id
    assert_nil report.cpuid_step
  end

  def test_rejects_a_wrong_sized_report
    error = assert_raises(Routex::ReportDecodeError) { Routex::AttestationReport.parse("short") }
    assert_match(/1184 bytes/, error.message)
  end

  # Mirrors ignoresReservedBytesWhenReportVersionIsUnknown upstream.
  def test_ignores_reserved_bytes_when_the_version_is_unknown
    bytes = patch(milan_v2_report_bytes, OFF_VERSION, [42, 0, 0, 0].pack("C4"))
    bytes = patch(bytes, OFF_RESERVED_TAIL, "\xAB".b * (OFF_SIGNATURE - OFF_RESERVED_TAIL))
    parsed = Routex::AttestationReport.parse(bytes)

    assert_equal 42, parsed.version
    refute_nil parsed.current_mit_vector
  end

  # Mirrors usesTurinTcbLayoutWhenCpuidFamIdIsUnknown upstream.
  def test_uses_the_turin_tcb_layout_when_the_cpuid_family_is_unknown
    bytes = patch(milan_v2_report_bytes, OFF_VERSION, [5, 0, 0, 0].pack("C4"))
    bytes = patch(bytes, OFF_CPUID_FAM_ID, "\xFF".b)

    refute_equal 0, Routex::AttestationReport.parse(bytes).current_tcb.fmc
  end

  # Mirrors rejectsLegacyReportWithFullyMaskedChipId upstream.
  def test_rejects_a_legacy_report_with_a_fully_masked_chip_id
    bytes = patch(milan_v2_report_bytes, OFF_CHIP_ID, "\x00".b * 64)
    error = assert_raises(Routex::ReportDecodeError) { Routex::AttestationReport.parse(bytes) }
    assert_match(/masked CHIP_ID/, error.message)
  end
end

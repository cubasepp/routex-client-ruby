# frozen_string_literal: true

require_relative "errors"

module Routex
  # SEV-SNP attestation report (AMD doc 56860). Port of AttestationReportParser.kt.
  class AttestationReport
    REPORT_LENGTH = 1184
    SIGNATURE_OFFSET = 0x2A0
    SIGNATURE_TBS_LENGTH = SIGNATURE_OFFSET
    SIGNATURE_LENGTH = 0x200
    ECDSA_SCALAR_LEN = 48
    ECDSA_SCALAR_SLOT_LEN = 72
    MILAN_GENOA_FAMILY = 0x19

    OFFSETS = {
      version: 0x00, guest_svn: 0x04, policy: 0x08, family_id: 0x10, image_id: 0x20,
      vmpl: 0x30, signature_algo: 0x34, current_tcb: 0x38, plat_info: 0x40,
      key_info: 0x48, report_data: 0x50, measurement: 0x90, host_data: 0xC0,
      id_key_digest: 0xE0, author_key_digest: 0x110, report_id: 0x140,
      report_id_ma: 0x160, reported_tcb: 0x180, cpuid_fam_id: 0x188,
      cpuid_mod_id: 0x189, cpuid_step: 0x18A, chip_id: 0x1A0, committed_tcb: 0x1E0,
      current_build: 0x1E8, current_minor: 0x1E9, current_major: 0x1EA,
      committed_build: 0x1EC, committed_minor: 0x1ED, committed_major: 0x1EE,
      launch_tcb: 0x1F0, launch_mit_vector: 0x1F8, current_mit_vector: 0x200
    }.freeze

    Tcb = Struct.new(:bootloader, :tee, :snp, :microcode, :fmc, :raw, keyword_init: true)
    FirmwareVersion = Struct.new(:major, :minor, :build, keyword_init: true) do
      def packed = (major << 16) | (minor << 8) | build
      def to_s = "#{major}.#{minor}.#{build}"
    end
    Signature = Struct.new(:algorithm, :r_little_endian, :s_little_endian, :raw, keyword_init: true)

    ECDSA_P384_SHA384 = 1

    attr_reader :version, :guest_svn, :policy, :vmpl, :signature_algo, :current_tcb,
                :reported_tcb, :committed_tcb, :launch_tcb, :platform_info, :key_info,
                :report_data, :measurement, :host_data, :chip_id, :cpuid_fam_id,
                :cpuid_mod_id, :cpuid_step, :current_version, :committed_version,
                :launch_mit_vector, :current_mit_vector, :signature, :raw

    def self.parse(bytes)
      bytes = bytes.b
      unless bytes.bytesize == REPORT_LENGTH
        raise ReportDecodeError, "attestation report must be #{REPORT_LENGTH} bytes, got #{bytes.bytesize}"
      end

      new(bytes)
    end

    def initialize(bytes)
      @raw = bytes
      @version = u32(:version)
      @guest_svn = u32(:guest_svn)
      turin_like = turin_like_layout?

      if @version >= 3
        @cpuid_fam_id = u8(:cpuid_fam_id)
        @cpuid_mod_id = u8(:cpuid_mod_id)
        @cpuid_step = u8(:cpuid_step)
      end

      @policy = parse_policy(u64(:policy))
      @vmpl = u32(:vmpl)
      @signature_algo = u32(:signature_algo)
      @current_tcb = parse_tcb(:current_tcb, turin_like)
      @reported_tcb = parse_tcb(:reported_tcb, turin_like)
      @committed_tcb = parse_tcb(:committed_tcb, turin_like)
      @launch_tcb = parse_tcb(:launch_tcb, turin_like)
      @platform_info = parse_platform_info(u64(:plat_info))
      @key_info = parse_key_info(u32(:key_info))

      @report_data = slice(:report_data, 64)
      @measurement = slice(:measurement, 48)
      @host_data = slice(:host_data, 32)
      @chip_id = slice(:chip_id, 64)

      @current_version = FirmwareVersion.new(
        major: u8(:current_major), minor: u8(:current_minor), build: u8(:current_build)
      )
      @committed_version = FirmwareVersion.new(
        major: u8(:committed_major), minor: u8(:committed_minor), build: u8(:committed_build)
      )

      if @version >= 5
        @launch_mit_vector = u64(:launch_mit_vector)
        @current_mit_vector = u64(:current_mit_vector)
      end

      @signature = parse_signature
    end

    def signed_bytes = @raw.byteslice(0, SIGNATURE_TBS_LENGTH)

    private

    # Milan/Genoa share family 0x19 and the legacy TCB layout; Turin and newer use
    # the Turin layout. Pre-v3 reports lack the cpuid fields, so fall back to the
    # CHIP_ID heuristic the Kotlin client uses.
    def turin_like_layout?
      return u8(:cpuid_fam_id) != MILAN_GENOA_FAMILY if @version >= 3

      chip_id = slice(:chip_id, 64)
      raise ReportDecodeError, "legacy report with fully masked CHIP_ID" if chip_id.each_byte.all?(&:zero?)

      chip_id.byteslice(8, 56).each_byte.all?(&:zero?)
    end

    def parse_tcb(field, turin_like)
      offset = OFFSETS.fetch(field)
      b = @raw.byteslice(offset, 8).unpack("C8")
      raw = u64(field)
      if turin_like
        Tcb.new(fmc: b[0], bootloader: b[1], tee: b[2], snp: b[3], microcode: b[7], raw: raw)
      else
        Tcb.new(fmc: 0, bootloader: b[0], tee: b[1], snp: b[6], microcode: b[7], raw: raw)
      end
    end

    def parse_policy(raw)
      {
        abi_minor: raw & 0xFF, abi_major: (raw >> 8) & 0xFF,
        smt_allowed: bit?(raw, 16), migrate_ma_allowed: bit?(raw, 18),
        debug_allowed: bit?(raw, 19), single_socket_required: bit?(raw, 20),
        cxl_allowed: bit?(raw, 21), mem_aes_256_xts: bit?(raw, 22),
        rapl_dis: bit?(raw, 23), ciphertext_hiding: bit?(raw, 24),
        page_swap_disabled: bit?(raw, 25), raw: raw
      }
    end

    def parse_platform_info(raw)
      {
        smt_enabled: bit?(raw, 0), tsme_enabled: bit?(raw, 1), ecc_enabled: bit?(raw, 2),
        rapl_disabled: bit?(raw, 3), ciphertext_hiding_enabled: bit?(raw, 4),
        alias_check_complete: bit?(raw, 5), tio_enabled: bit?(raw, 7), raw: raw
      }
    end

    def parse_key_info(raw)
      signing_key = (raw >> 2) & 0x7
      kind = { 0 => :vcek, 1 => :vlek, 7 => :none }.fetch(signing_key, :other)
      {
        author_key_en: (raw & 1) != 0, mask_chip_key: ((raw >> 1) & 1) != 0,
        signing_key: signing_key, signing_key_kind: kind, raw: raw
      }
    end

    def parse_signature
      raw = @raw.byteslice(SIGNATURE_OFFSET, SIGNATURE_LENGTH)
      return Signature.new(algorithm: @signature_algo, r_little_endian: "", s_little_endian: "", raw: raw) unless
        @signature_algo == ECDSA_P384_SHA384

      Signature.new(
        algorithm: @signature_algo,
        r_little_endian: raw.byteslice(0, ECDSA_SCALAR_LEN),
        s_little_endian: raw.byteslice(ECDSA_SCALAR_SLOT_LEN, ECDSA_SCALAR_LEN),
        raw: raw
      )
    end

    def bit?(raw, index) = ((raw >> index) & 1) != 0
    def slice(field, len) = @raw.byteslice(OFFSETS.fetch(field), len)
    def u8(field) = @raw.getbyte(OFFSETS.fetch(field))
    def u32(field) = @raw.byteslice(OFFSETS.fetch(field), 4).unpack1("L<")
    def u64(field) = @raw.byteslice(OFFSETS.fetch(field), 8).unpack1("Q<")
  end
end

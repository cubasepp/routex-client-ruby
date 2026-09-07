# frozen_string_literal: true

module Routex
  # Minimum platform state a TEE must attest to before the client will talk to it.
  #
  # These constants track AMD security bulletins and are the part of this library
  # that MUST be kept in sync with the upstream Kotlin client (Requirements.kt).
  # Loosening them silently weakens every connection; see PORTING.md.
  module Requirements
    MIT_BIT = ->(n) { 1 << n }

    PerProduct = Struct.new(:min_committed_version, :min_committed_tcb_snp,
                            :fallback_microcode, :min_mit_vector, keyword_init: true) do
      def initialize(min_mit_vector: 0, **rest)
        super
      end
    end

    def self.version(major, minor, build)
      AttestationReport::FirmwareVersion.new(major: major, minor: minor, build: build)
    end

    # AMD SB-3023. Mirrors Requirements.Sb3023 in the Kotlin client.
    module Sb3023
      MILAN = PerProduct.new(
        min_committed_version: Requirements.version(0x1, 0x37, 0x23),
        min_committed_tcb_snp: 0x1B, fallback_microcode: 0xDE,
        min_mit_vector: MIT_BIT[1]
      )
      GENOA = PerProduct.new(
        min_committed_version: Requirements.version(0x1, 0x37, 0x31),
        min_committed_tcb_snp: 0x1B, fallback_microcode: 0x56,
        min_mit_vector: MIT_BIT[0] | MIT_BIT[1]
      )
      TURIN = PerProduct.new(
        min_committed_version: Requirements.version(0x1, 0x37, 0x41),
        min_committed_tcb_snp: 0x04, fallback_microcode: 0x50,
        min_mit_vector: MIT_BIT[0] | MIT_BIT[1] | MIT_BIT[2] | MIT_BIT[4] | MIT_BIT[5]
      )

      MICROCODE = {
        milan: { [1, 1] => 0xDE, [1, 2] => 0x47 },
        genoa: { [0x11, 1] => 0x56, [0x11, 2] => 0x51, [0xA0, 2] => 0x1B },
        turin: { [2, 1] => 0x51, [0x11, 0] => 0x4E }
      }.freeze

      def self.for_family(family)
        { milan: MILAN, genoa: GENOA, turin: TURIN }.fetch(family)
      end

      def self.min_microcode(family, model, stepping)
        MICROCODE.fetch(family).fetch([model, stepping], nil)
      end

      def self.pinned? = true
    end

    # Structural checks only: signature, scalar padding and reported-TCB-vs-VCEK.
    # For diagnostics; never use against production endpoints.
    module Permissive
      def self.pinned? = false
    end

    DEFAULT = Sb3023
  end
end

# frozen_string_literal: true

require_relative "vcek_certificate"

module Routex
  # AMD ARK/ASK trust anchors for Milan, Genoa and Turin, copied verbatim from the
  # upstream Kotlin client's AmdRootStore.kt.
  module AmdRootStore
    PEM_PATH = File.expand_path("certs/amd_roots.pem", __dir__)

    def self.certificates
      @certificates ||= VcekCertificate.parse_chain(File.read(PEM_PATH)).freeze
    end
  end
end

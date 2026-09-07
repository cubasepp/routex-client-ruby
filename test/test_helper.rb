# frozen_string_literal: true

require "minitest/autorun"
require "base64"
require "routex"

module TestHelpers
  FIXTURES = File.expand_path("fixtures", __dir__)

  def unhex(string) = [string].pack("H*")
  def hex(bytes) = bytes.unpack1("H*")

  def milan_v2_report_bytes
    Base64.strict_decode64(File.read(File.join(FIXTURES, "attestation_report_milan_v2.b64")).strip)
  end

  def patch(bytes, offset, replacement)
    copy = bytes.dup
    copy[offset, replacement.bytesize] = replacement
    copy
  end
end

class Minitest::Test
  include TestHelpers
end

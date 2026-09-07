# frozen_string_literal: true

require "base64"

module Routex
  # Ed25519 public keys YAXI signs system-version entries with, pinned in the
  # client. Copied from YaxiSystemVersionKeys.kt; must be kept in sync with
  # upstream (see PORTING.md).
  module YaxiSystemVersionKeys
    DEFAULT = {
      "AhrUXsV/XAvIE24RQ/Vt/zXoLodvjXoWD2fhLGuRM7U=" =>
        Base64.strict_decode64("ZbxMIfWbKk/WtX0xRIVX6Htb0RXvJMPXUoygw+xvtOI="),
      "D30zRYe8Ug9732b4Pe2BAwWAXn/T5Nss2HJOp3kLC1w=" =>
        Base64.strict_decode64("CMtrYRGMEPAdxWgas3NWAtJJa9MuIlmudcF+1wyFaiU=")
    }.freeze
  end
end

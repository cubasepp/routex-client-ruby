# frozen_string_literal: true

require "openssl"
require "securerandom"
require_relative "errors"
require_relative "crypto/blake2b"

module Routex
  # Platform crypto surface consumed by settlement verification. Every function
  # takes and returns raw binary strings; no OpenSSL types leak out.
  #
  # Mirrors settlement/src/commonMain/.../internal/CryptoPrimitives.kt, whose JVM
  # actual is backed by BouncyCastle. Outputs are pinned against that
  # implementation in test/crypto_test.rb.
  module Crypto
    X25519_KEY_BYTES = 32
    CHACHA_KEY_BYTES = 32
    POLY1305_TAG_BYTES = 16
    NONCE_BYTES = 12

    module_function

    def sha256(bytes)
      OpenSSL::Digest.digest("SHA256", bytes)
    end

    def blake2b_digest(message, out_len)
      Blake2b.digest(message, out_len)
    end

    # HKDF (RFC 5869) over BLAKE2b-512 with an empty salt.
    #
    # OpenSSL::KDF.hkdf cannot be used here: OpenSSL 3's HKDF is restricted to the
    # digests registered with its KDF provider and rejects BLAKE2b512. HMAC over
    # BLAKE2b512 is available, so extract-and-expand is done explicitly. This is
    # the same construction as BouncyCastle's HKDFBytesGenerator(Blake2bDigest(512)).
    def hkdf_blake2b512(ikm, info, length)
      md = OpenSSL::Digest.new("BLAKE2b512")
      prk = OpenSSL::HMAC.digest(md, "\x00" * md.digest_length, ikm)
      okm = +""
      block = +""
      counter = 1
      while okm.bytesize < length
        block = OpenSSL::HMAC.digest(md, prk, block + info + counter.chr)
        okm << block
        counter += 1
      end
      okm.byteslice(0, length)
    end

    def chacha20_poly1305_encrypt(key, nonce, plaintext)
      cipher = OpenSSL::Cipher.new("chacha20-poly1305").encrypt
      cipher.key = key
      cipher.iv = nonce
      ciphertext = cipher.update(plaintext) + cipher.final
      ciphertext + cipher.auth_tag(POLY1305_TAG_BYTES)
    end

    def chacha20_poly1305_decrypt(key, nonce, ciphertext_with_tag)
      if ciphertext_with_tag.bytesize < POLY1305_TAG_BYTES
        raise Error, "ciphertext shorter than the Poly1305 tag"
      end

      split = ciphertext_with_tag.bytesize - POLY1305_TAG_BYTES
      cipher = OpenSSL::Cipher.new("chacha20-poly1305").decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_tag = ciphertext_with_tag.byteslice(split, POLY1305_TAG_BYTES)
      cipher.update(ciphertext_with_tag.byteslice(0, split)) + cipher.final
    end

    def x25519_shared_secret(my_secret, their_public)
      check_key_length!(my_secret, "secret")
      check_key_length!(their_public, "public")
      priv = OpenSSL::PKey.new_raw_private_key("X25519", my_secret)
      pub = OpenSSL::PKey.new_raw_public_key("X25519", their_public)
      priv.derive(pub)
    end

    def x25519_generate_key_pair
      key = OpenSSL::PKey.generate_key("X25519")
      [key.raw_private_key, key.raw_public_key]
    end

    def x25519_public_key(secret)
      check_key_length!(secret, "secret")
      OpenSSL::PKey.new_raw_private_key("X25519", secret).raw_public_key
    end

    def ed25519_verify(public_key, message, signature)
      OpenSSL::PKey.new_raw_public_key("ED25519", public_key)
                   .verify(nil, signature, message)
    rescue OpenSSL::PKey::PKeyError, OpenSSL::OpenSSLError
      false
    end

    # SEV-SNP attestation reports carry the ECDSA signature as raw big-endian r and
    # s scalars; OpenSSL expects DER SEQUENCE { INTEGER r, INTEGER s }.
    def ecdsa_raw_to_der(r_big_endian, s_big_endian)
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(r_big_endian, 2)),
        OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(s_big_endian, 2))
      ]).to_der
    end

    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end

    def check_key_length!(key, label)
      return if key.bytesize == X25519_KEY_BYTES

      raise ArgumentError, "X25519 #{label} key must be #{X25519_KEY_BYTES} bytes, got #{key.bytesize}"
    end
  end
end

# frozen_string_literal: true

require_relative "test_helper"

# Golden values marked "BouncyCastle" were produced by running the upstream Kotlin
# client's jvmAndAndroidMain primitives (BouncyCastle 1.78.1) on the same inputs.
# They are what makes this port verifiably wire-compatible rather than merely
# plausible; see PORTING.md.
class CryptoTest < Minitest::Test
  def test_sha256
    assert_equal "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                 hex(Routex::Crypto.sha256("abc"))
  end

  def test_blake2b_512_matches_rfc_7693
    assert_equal "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" \
                 "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                 hex(Routex::Crypto.blake2b_digest("abc", 64))
  end

  # The ChaChaBox nonce length. libsodium's wrapper refuses digests under 16 bytes
  # and OpenSSL only has the fixed 64-byte BLAKE2b512, so this is the case the
  # bundled implementation exists for.
  def test_blake2b_12_matches_bouncycastle
    assert_equal "48b4f1f9042a2d5033b382b5", hex(Routex::Crypto.blake2b_digest("abc", 12))
  end

  def test_blake2b_is_not_a_truncated_blake2b_512
    refute_equal Routex::Crypto.blake2b_digest("abc", 64).byteslice(0, 12),
                 Routex::Crypto.blake2b_digest("abc", 12)
  end

  def test_blake2b_across_block_boundaries
    [0, 1, 127, 128, 129, 255, 256, 1000].each do |length|
      message = "z" * length
      assert_equal OpenSSL::Digest.new("BLAKE2b512").digest(message),
                   Routex::Crypto.blake2b_digest(message, 64),
                   "BLAKE2b-512 mismatch at message length #{length}"
    end
  end

  def test_blake2b_rejects_out_of_range_lengths
    assert_raises(ArgumentError) { Routex::Crypto.blake2b_digest("abc", 0) }
    assert_raises(ArgumentError) { Routex::Crypto.blake2b_digest("abc", 65) }
  end

  def test_hkdf_blake2b512_matches_bouncycastle
    assert_equal "d60f29356ba9332aaf32a9e7746d1982e572282e6a834116fb0c24e735b977df",
                 hex(Routex::Crypto.hkdf_blake2b512(unhex("0b" * 32), unhex("cafebabe" * 8), 32))
  end

  def test_hkdf_expands_past_one_block
    okm = Routex::Crypto.hkdf_blake2b512(unhex("0b" * 32), "info", 200)
    assert_equal 200, okm.bytesize
    assert_equal okm.byteslice(0, 32), Routex::Crypto.hkdf_blake2b512(unhex("0b" * 32), "info", 32)
  end

  def test_x25519_matches_rfc_7748
    secret = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    peer = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert_equal "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                 hex(Routex::Crypto.x25519_shared_secret(secret, peer))
  end

  def test_x25519_rejects_wrong_key_length
    assert_raises(ArgumentError) { Routex::Crypto.x25519_shared_secret("short", "\x00" * 32) }
  end

  def test_chacha20_poly1305_matches_rfc_8439
    key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = unhex("070000004041424344454647")
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip " \
                "for the future, sunscreen would be it."
    sealed = Routex::Crypto.chacha20_poly1305_encrypt(key, nonce, plaintext)
    assert_equal "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
                 hex(sealed)[0, 64]
    assert_equal plaintext, Routex::Crypto.chacha20_poly1305_decrypt(key, nonce, sealed)
  end

  def test_ecdsa_raw_to_der_round_trips
    key = OpenSSL::PKey::EC.generate("secp384r1")
    message = "attestation report body"
    asn1 = OpenSSL::ASN1.decode(key.sign(OpenSSL::Digest.new("SHA384"), message))
    r = asn1.value[0].value.to_s(2).rjust(48, "\x00")
    s = asn1.value[1].value.to_s(2).rjust(48, "\x00")

    assert key.verify(OpenSSL::Digest.new("SHA384"), Routex::Crypto.ecdsa_raw_to_der(r, s), message)
  end

  def test_ed25519_verify_round_trip
    key = OpenSSL::PKey.generate_key("ED25519")
    signature = key.sign(nil, "message")
    public_key = key.raw_public_key

    assert Routex::Crypto.ed25519_verify(public_key, "message", signature)
    refute Routex::Crypto.ed25519_verify(public_key, "tampered", signature)
  end

  def test_ed25519_verify_returns_false_on_malformed_key
    refute Routex::Crypto.ed25519_verify("too short", "message", "signature")
  end
end

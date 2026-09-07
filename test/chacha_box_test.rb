# frozen_string_literal: true

require_relative "test_helper"

class ChaChaBoxTest < Minitest::Test
  EPHEMERAL_SECRET = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  RECIPIENT_SECRET = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  PLAINTEXT = '{"publicKey":"AAA","sessionId":"s-1"}'

  # Produced by the upstream Kotlin ChaChaBox.sealV1 running on BouncyCastle with
  # the ephemeral key above injected. If this test fails, the Ruby client can no
  # longer talk to the YAXI TEE.
  BOUNCYCASTLE_SEALED =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" \
    "6e457b14d031146b520f99a564d6b7f2ae9908ef3a6c537aee924abb6425ab64" \
    "bbd95a95850e947aee6fb815bf5ae28c67e73a44df"

  def setup
    @ephemeral = Routex::ChaChaBox::Keys.new(
      secret: unhex(EPHEMERAL_SECRET),
      public: Routex::Crypto.x25519_public_key(unhex(EPHEMERAL_SECRET))
    )
    @recipient = Routex::ChaChaBox::Keys.new(
      secret: unhex(RECIPIENT_SECRET),
      public: Routex::Crypto.x25519_public_key(unhex(RECIPIENT_SECRET))
    )
  end

  def test_seal_matches_bouncycastle_byte_for_byte
    sealed = Routex::ChaChaBox.seal_with_ephemeral(@ephemeral, @recipient.public, PLAINTEXT)
    assert_equal BOUNCYCASTLE_SEALED, hex(sealed)
  end

  def test_unseals_a_bouncycastle_ciphertext
    assert_equal PLAINTEXT, Routex::ChaChaBox.unseal(@recipient, unhex(BOUNCYCASTLE_SEALED))
  end

  def test_round_trip_with_a_fresh_ephemeral_key
    sealed = Routex::ChaChaBox.seal(@recipient.public, PLAINTEXT)
    assert_equal PLAINTEXT, Routex::ChaChaBox.unseal(@recipient, sealed)
  end

  def test_rejects_a_tampered_ciphertext
    sealed = unhex(BOUNCYCASTLE_SEALED).dup
    sealed.setbyte(40, sealed.getbyte(40) ^ 0xFF)
    assert_raises(Routex::ChaChaBox::DecryptError) { Routex::ChaChaBox.unseal(@recipient, sealed) }
  end

  def test_rejects_a_tampered_ephemeral_header
    sealed = unhex(BOUNCYCASTLE_SEALED).dup
    sealed.setbyte(0, sealed.getbyte(0) ^ 0x01)
    assert_raises(Routex::ChaChaBox::DecryptError) { Routex::ChaChaBox.unseal(@recipient, sealed) }
  end

  def test_rejects_a_short_ciphertext
    error = assert_raises(Routex::ChaChaBox::DecryptError) do
      Routex::ChaChaBox.unseal(@recipient, "\x00" * 47)
    end
    assert_match(/too short/, error.message)
  end

  def test_generated_keys_agree
    keys = Routex::ChaChaBox.generate_keys
    assert_equal 32, keys.secret.bytesize
    assert_equal keys.public, Routex::Crypto.x25519_public_key(keys.secret)
  end
end

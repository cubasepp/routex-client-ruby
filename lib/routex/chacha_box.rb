# frozen_string_literal: true

require_relative "crypto"
require_relative "errors"

module Routex
  # X25519 ephemeral-static ECDH keyed through HKDF-BLAKE2b-512 into
  # ChaCha20-Poly1305. Wire format is `ephemeral_public(32) || ciphertext || tag(16)`.
  #
  # Port of settlement/src/commonMain/.../ChaChaBox.kt.
  module ChaChaBox
    HEAD_BYTES = Crypto::X25519_KEY_BYTES
    MIN_CIPHERTEXT_BYTES = HEAD_BYTES + Crypto::POLY1305_TAG_BYTES

    Keys = Struct.new(:secret, :public, keyword_init: true)

    module_function

    def generate_keys
      secret, public_key = Crypto.x25519_generate_key_pair
      Keys.new(secret: secret, public: public_key)
    end

    def seal(recipient_public_key, plaintext)
      seal_with_ephemeral(generate_keys, recipient_public_key, plaintext)
    end

    def unseal(client_keys, ciphertext)
      if ciphertext.bytesize < MIN_CIPHERTEXT_BYTES
        raise DecryptError, "ciphertext too short: #{ciphertext.bytesize} < #{MIN_CIPHERTEXT_BYTES}"
      end

      ephemeral_public = ciphertext.byteslice(0, HEAD_BYTES)
      body = ciphertext.byteslice(HEAD_BYTES, ciphertext.bytesize - HEAD_BYTES)
      key = derive_key(client_keys.secret, ephemeral_public, ephemeral_public, client_keys.public)

      begin
        Crypto.chacha20_poly1305_decrypt(key, nonce(ephemeral_public, client_keys.public), body)
      rescue OpenSSL::OpenSSLError, Error => e
        raise DecryptError, "chacha20-poly1305 decryption failed: #{e.message}"
      end
    end

    # Exposed so golden vectors can pin the ephemeral key; production callers use #seal.
    def seal_with_ephemeral(ephemeral, recipient_public_key, plaintext)
      key = derive_key(ephemeral.secret, recipient_public_key, ephemeral.public, recipient_public_key)
      ephemeral.public + Crypto.chacha20_poly1305_encrypt(
        key, nonce(ephemeral.public, recipient_public_key), plaintext
      )
    end

    def derive_key(secret, peer_public, info_a, info_b)
      shared = Crypto.x25519_shared_secret(secret, peer_public)
      Crypto.hkdf_blake2b512(shared, info_a + info_b, Crypto::CHACHA_KEY_BYTES)
    end

    def nonce(a, b)
      Crypto.blake2b_digest(a + b, Crypto::NONCE_BYTES)
    end
  end
end

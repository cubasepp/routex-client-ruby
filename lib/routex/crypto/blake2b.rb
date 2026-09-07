# frozen_string_literal: true

module Routex
  module Crypto
    # BLAKE2b (RFC 7693) with a caller-chosen digest length.
    #
    # OpenSSL only exposes the fixed 64-byte BLAKE2b512, and libsodium's
    # crypto_generichash wrapper in rbnacl refuses digests below 16 bytes. The
    # ChaChaBox nonce is 12 bytes, and a 12-byte BLAKE2b is not a truncated
    # BLAKE2b-512 -- the digest length is mixed into the parameter block -- so
    # neither can produce it. Hence this implementation.
    module Blake2b
      MASK = 0xFFFF_FFFF_FFFF_FFFF
      BLOCK_BYTES = 128
      MAX_DIGEST_BYTES = 64

      IV = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
      ].freeze

      SIGMA = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
      ].freeze

      module_function

      def digest(message, out_len = MAX_DIGEST_BYTES)
        unless out_len.is_a?(Integer) && out_len.between?(1, MAX_DIGEST_BYTES)
          raise ArgumentError, "digest length must be 1..#{MAX_DIGEST_BYTES}, got #{out_len.inspect}"
        end

        state = IV.dup
        state[0] ^= 0x01010000 ^ out_len

        bytes = message.b
        total = bytes.bytesize
        offset = 0
        while total - offset > BLOCK_BYTES
          offset += BLOCK_BYTES
          compress(state, bytes.byteslice(offset - BLOCK_BYTES, BLOCK_BYTES), offset, false)
        end
        tail = bytes.byteslice(offset, total - offset) || ""
        compress(state, tail.ljust(BLOCK_BYTES, "\x00"), total, true)

        state.pack("Q<8").byteslice(0, out_len)
      end

      def compress(state, block, counter, last)
        v = state + IV
        v[12] ^= counter & MASK
        v[13] ^= (counter >> 64) & MASK
        v[14] ^= MASK if last

        m = block.unpack("Q<16")
        12.times do |round|
          s = SIGMA[round % 10]
          mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
          mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
          mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
          mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
          mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
          mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
          mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
          mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        end

        8.times { |i| state[i] ^= v[i] ^ v[i + 8] }
        state
      end

      def mix(v, a, b, c, d, x, y)
        v[a] = (v[a] + v[b] + x) & MASK
        v[d] = rotr64(v[d] ^ v[a], 32)
        v[c] = (v[c] + v[d]) & MASK
        v[b] = rotr64(v[b] ^ v[c], 24)
        v[a] = (v[a] + v[b] + y) & MASK
        v[d] = rotr64(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & MASK
        v[b] = rotr64(v[b] ^ v[c], 63)
      end

      def rotr64(x, n)
        ((x >> n) | (x << (64 - n))) & MASK
      end
    end
  end
end

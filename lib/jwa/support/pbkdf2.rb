module JWA
  module Support
    class PBKDF2
      def initialize(hash)
        @hash = hash
      end

      def run_hex(password, salt, iterations, key_length = nil)
        run(password, salt, iterations, key_length).unpack('H*').first
      end

      def run(password, salt, iterations, key_length = nil)
        key_length ||= @hash.size

        blocks_needed = (key_length / @hash.size.to_f).ceil

        v = 1.upto(blocks_needed).map do |block_num|
          calculate_block(block_num, salt, password, iterations)
        end.join

        v[0...key_length]
      end

      def calculate_block(block_num, salt, password, iterations)
        u = prf(salt + [block_num].pack('N'), password)
        ret = u

        2.upto(iterations) do
          u = prf(u, password)
          ret = xor(ret, u)
        end

        ret
      end

      private

      def prf(data, password)
        OpenSSL::HMAC.digest(@hash, password, data)
      end

      def xor(s1, s2)
        result = (0..s1.length - 1).collect { |i| s1[i].ord ^ s2[i].ord }
        result.pack('C*')
      end
    end
  end
end

module JWA
  module Support
    class ConcatKDF
      def initialize(hash)
        @hash = hash
        @default_key_len = hash.size * 8
      end

      def run(z, other_info, key_data_len = nil)
        key_data_len ||= @default_key_len
        reps = (key_data_len / @default_key_len.to_f).ceil

        derive_key(reps, key_data_len, z, other_info)
      end

      def derive_key(reps, key_data_len, z, other_info)
        key_material = ''
        data = z + other_info

        (1..reps).each do |n|
          concatenation = [n, data].pack('Na*')
          key_material += @hash.digest(concatenation)
        end

        key_material[0...key_data_len / 8]
      end
    end
  end
end

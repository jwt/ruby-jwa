module JWA
  module Algorithms
    module KeyManagement
      class EcdhEs
        def initialize(ephemeral_key, enc_algorithm, apu, apv)
          @ephemeral_key = ephemeral_key
          @key_length = enc_algorithm.key_length * 8

          algorithm_id = length_encode(enc_algorithm.enc_name)
          apu = length_encode(apu)
          apv = length_encode(apv)
          supp_pub_info = [@key_length].pack('N')
          supp_priv_info = ''

          @info = algorithm_id + apu + apv + supp_pub_info + supp_priv_info
        end

        # This is technically not an encryption, but to keep the same interface
        # with other classes, let's name it this way.
        def encrypt(public_key)
          z = @ephemeral_key.dh_compute_key(public_key)

          concat_kdf = Support::ConcatKDF.new(Digest::SHA256.new)
          concat_kdf.run(z, @info, @key_length)
        end

        def decrypt(public_key)
          encrypt(public_key)
        end

        private

        def length_encode(s)
          [s.length].pack('N') + s
        end
      end
    end
  end
end

module JWA
  module Algorithms
    module KeyManagement
      # RSA-OAEP key encryption algorithm.
      class RsaOaep
        def initialize(key)
          @key = key
        end

        def encrypt(plaintext)
          @key.public_encrypt(plaintext, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        end

        def decrypt(ciphertext)
          @key.private_decrypt(ciphertext, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        end
      end
    end
  end
end

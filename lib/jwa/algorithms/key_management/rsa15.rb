module JWA
  module Algorithms
    module KeyManagement
      # RSA RSA with PKCS1 v1.5 algorithm.
      class Rsa15
        def initialize(key)
          @key = key
        end

        def encrypt(plaintext)
          @key.public_encrypt(plaintext)
        end

        def decrypt(ciphertext)
          @key.private_decrypt(ciphertext)
        end
      end
    end
  end
end

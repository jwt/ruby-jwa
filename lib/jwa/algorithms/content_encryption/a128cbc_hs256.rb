require 'jwa/algorithms/content_encryption/aes_cbc_hs'

module JWA
  module Algorithms
    module ContentEncryption
      class A128cbcHs256
        include AesCbcHs

        class << self
          def key_length
            32
          end

          def cipher_name
            'AES-128-CBC'
          end

          def hash_name
            'sha256'
          end
        end
      end
    end
  end
end

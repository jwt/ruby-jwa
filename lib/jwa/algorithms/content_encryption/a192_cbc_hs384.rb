require 'jwa/algorithms/content_encryption/aes_cbc_hs'

module JWA
  module Algorithms
    module ContentEncryption
      class A192CbcHs384
        include AesCbcHs

        class << self
          def key_length
            48
          end

          def cipher_name
            'AES-192-CBC'
          end

          def hash_name
            'sha384'
          end
        end
      end
    end
  end
end

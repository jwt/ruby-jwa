require 'jwa/algorithms/content_encryption/aes_cbc_hs'

module JWA
  module Algorithms
    module ContentEncryption
      class A256CbcHs512
        include AesCbcHs

        class << self
          def key_length
            64
          end

          def cipher_name
            'AES-256-CBC'
          end

          def hash_name
            'sha512'
          end
        end
      end
    end
  end
end

require 'jwa/algorithms/content_encryption/aes_cbc_hs'

module JWA
  module Algorithms
    module ContentEncryption
      class A128CbcHs256
        include AesCbcHs

        class << self
          def enc_name
            'A128CBC-HS256'
          end

          def key_length
            32
          end

          def cipher_name
            'AES-128-CBC'
          end

          def hash
            OpenSSL::Digest::SHA256.new
          end
        end
      end
    end
  end
end

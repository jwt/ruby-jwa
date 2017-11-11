require 'jwa/algorithms/content_encryption/aes_gcm'

module JWA
  module Algorithms
    module ContentEncryption
      class A128Gcm
        include AesGcm

        class << self
          def key_length
            16
          end

          def cipher_name
            'aes-128-gcm'
          end
        end
      end
    end
  end
end

require 'jwa/algorithms/content_encryption/aes_gcm'

module JWA
  module Algorithms
    module ContentEncryption
      class A192Gcm
        include AesGcm

        class << self
          def enc_name
            'A192GCM'
          end

          def key_length
            24
          end

          def cipher_name
            'aes-192-gcm'
          end
        end
      end
    end
  end
end

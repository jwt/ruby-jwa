require 'jwa/algorithms/content_encryption/aes_gcm'

module JWA
  module Algorithms
    module ContentEncryption
      class A256Gcm
        include AesGcm

        class << self
          def key_length
            32
          end

          def cipher_name
            'aes-256-gcm'
          end
        end
      end
    end
  end
end

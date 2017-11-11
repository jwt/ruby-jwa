require 'jwa/algorithms/key_management/aes_gcm_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A256GcmKw
        include AesGcmKw

        class << self
          def key_length
            32
          end

          def cipher
            A256Gcm
          end
        end
      end
    end
  end
end

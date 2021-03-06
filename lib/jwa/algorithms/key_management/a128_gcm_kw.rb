require 'jwa/algorithms/key_management/aes_gcm_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A128GcmKw
        include AesGcmKw

        class << self
          def key_length
            16
          end

          def cipher
            A128Gcm
          end
        end
      end
    end
  end
end

require 'jwa/algorithms/key_management/aes_gcm_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A128GcmKw
        include AesGcmKw

        class << self
          def cipher
            A128gcm
          end
        end
      end
    end
  end
end

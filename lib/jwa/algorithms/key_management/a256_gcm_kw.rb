require 'jwa/algorithms/key_management/aes_gcm_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A256GcmKw
        include AesGcmKw

        class << self
          def cipher
            A256gcm
          end
        end
      end
    end
  end
end

require 'jwa/algorithms/key_management/aes_gcm_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A192GcmKw
        include AesGcmKw

        class << self
          def cipher
            A192gcm
          end
        end
      end
    end
  end
end

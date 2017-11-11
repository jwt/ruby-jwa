require 'jwa/algorithms/key_management/aes_gcm_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A192GcmKw
        include AesGcmKw

        class << self
          def key_length
            24
          end

          def cipher
            A192Gcm
          end
        end
      end
    end
  end
end

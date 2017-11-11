require 'jwa/algorithms/key_management/aes_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A192Kw
        include AesKw

        class << self
          def key_length
            24
          end

          def cipher_name
            'AES-192-ECB'
          end
        end
      end
    end
  end
end

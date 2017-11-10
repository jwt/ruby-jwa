require 'jwa/algorithms/key_management/aes_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A192Kw
        include AesKw

        class << self
          def cipher_name
            'AES-192-ECB'
          end
        end
      end
    end
  end
end

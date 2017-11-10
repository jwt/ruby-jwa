require 'jwa/algorithms/key_management/aes_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A128Kw
        include AesKw

        class << self
          def cipher_name
            'AES-128-ECB'
          end
        end
      end
    end
  end
end

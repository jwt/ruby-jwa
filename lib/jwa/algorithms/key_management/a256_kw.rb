require 'jwa/algorithms/key_management/aes_kw'

module JWA
  module Algorithms
    module KeyManagement
      class A256Kw
        include AesKw

        class << self
          def cipher_name
            'AES-256-ECB'
          end
        end
      end
    end
  end
end

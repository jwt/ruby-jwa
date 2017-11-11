require 'jwa/algorithms/key_management/ecdh_es_kw'

module JWA
  module Algorithms
    module KeyManagement
      class EcdhEsA128Kw
        include EcdhEsKw

        class << self
          def alg_name
            'ECDH-ES+A128KW'
          end

          def shared_key_length
            16
          end

          def kw_class
            A128Kw
          end
        end
      end
    end
  end
end

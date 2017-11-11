require 'jwa/algorithms/key_management/ecdh_es_kw'

module JWA
  module Algorithms
    module KeyManagement
      class EcdhEsA128kw
        include EcdhEsKw

        class << self
          def alg_name
            'ECDH-ES+A192KW'
          end

          def shared_key_length
            24
          end

          def kw_class
            A192Kw
          end
        end
      end
    end
  end
end

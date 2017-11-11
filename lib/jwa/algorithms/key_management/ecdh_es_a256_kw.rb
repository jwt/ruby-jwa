require 'jwa/algorithms/key_management/ecdh_es_kw'

module JWA
  module Algorithms
    module KeyManagement
      class EcdhEsA256Kw
        include EcdhEsKw

        class << self
          def alg_name
            'ECDH-ES+A256KW'
          end

          def shared_key_length
            32
          end

          def kw_class
            A256Kw
          end
        end
      end
    end
  end
end

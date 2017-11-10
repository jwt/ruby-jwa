require 'jwa/algorithms/key_management/pbes2'

module JWA
  module Algorithms
    module KeyManagement
      class Pbes2Hs256A128Kw
        include Pbes2

        class << self
          def alg_name
            'PBES2-HS256+A128KW'
          end

          def kw_class
            A128Kw
          end

          def key_length
            16
          end
        end
      end
    end
  end
end

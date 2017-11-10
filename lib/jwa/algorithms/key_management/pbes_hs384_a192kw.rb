require 'jwa/algorithms/key_management/pbes2'

module JWA
  module Algorithms
    module KeyManagement
      class Pbes2Hs384A192Kw
        include Pbes2

        class << self
          def alg_name
            'PBES2-HS384+A192KW'
          end

          def kw_class
            A192Kw
          end

          def key_length
            24
          end
        end
      end
    end
  end
end

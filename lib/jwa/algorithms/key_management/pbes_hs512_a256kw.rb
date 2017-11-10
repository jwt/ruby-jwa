require 'jwa/algorithms/key_management/pbes2'

module JWA
  module Algorithms
    module KeyManagement
      class Pbes2Hs512A256Kw
        include Pbes2

        class << self
          def alg_name
            'PBES2-HS512+A256KW'
          end

          def kw_class
            A256Kw
          end

          def key_length
            32
          end
        end
      end
    end
  end
end

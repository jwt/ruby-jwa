require 'jwa/algorithms/key_management/ecdh_es'

module JWA
  module Algorithms
    module KeyManagement
      module EcdhEsKw
        def initialize(private_key, apu, apv)
          @inner = EcdhEs.new(private_key, self.class.shared_key_length, self.class.alg_name, apu, apv)
        end

        def encrypt(public_key, content)
          key = @inner.encrypt(public_key)
          self.class.kw_class.new(key).encrypt(content)
        end

        def decrypt(public_key, content)
          key = @inner.encrypt(public_key)
          self.class.kw_class.new(key).decrypt(content)
        end
      end
    end
  end
end

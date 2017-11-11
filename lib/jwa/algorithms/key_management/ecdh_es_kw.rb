require 'jwa/algorithms/key_management/ecdh_es'

module JWA
  module Algorithms
    module KeyManagement
      module EcdhEsKw
        def initialize(ephemeral_key, apu, apv)
          @inner = EcdhEs.new(ephemeral_key, self.class.shared_key_length, self.class.alg_name, apu, apv)
        end

        def encrypt(public_key, plaintext)
          key = @inner.encrypt(public_key)
          self.class.kw_class.new(key).encrypt(plaintext)
        end

        def decrypt(public_key, ciphertext)
          key = @inner.decrypt(public_key)
          self.class.kw_class.new(key).decrypt(ciphertext)
        end
      end
    end
  end
end

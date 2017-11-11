require 'jwa/algorithms/key_management/rsa15'
require 'jwa/algorithms/key_management/rsa_oaep'

require 'jwa/algorithms/key_management/a128_kw'
require 'jwa/algorithms/key_management/a192_kw'
require 'jwa/algorithms/key_management/a256_kw'

require 'jwa/algorithms/key_management/ecdh_es'
require 'jwa/algorithms/key_management/ecdh_es_a128_kw'
require 'jwa/algorithms/key_management/ecdh_es_a192_kw'
require 'jwa/algorithms/key_management/ecdh_es_a256_kw'

require 'jwa/algorithms/key_management/a128_gcm_kw'
require 'jwa/algorithms/key_management/a192_gcm_kw'
require 'jwa/algorithms/key_management/a256_gcm_kw'

require 'jwa/algorithms/key_management/pbes_hs256_a128_kw'
require 'jwa/algorithms/key_management/pbes_hs384_a192_kw'
require 'jwa/algorithms/key_management/pbes_hs512_a256_kw'

module JWA
  module Algorithms
    module KeyManagement
      KNOWN_ALGS = {
        'RSA1_5' => Rsa15,
        'RSA-OAEP' => RsaOaep,
        'RSA-OAEP-256' => nil,

        'A128KW' => A128Kw,
        'A192KW' => A192Kw,
        'A256KW' => A256Kw,

        'dir' => nil,

        'ECDH-ES' => EcdhEs,
        'ECDH-ES+A128KW' => EcdhEs,
        'ECDH-ES+A192KW' => EcdhEs,
        'ECDH-ES+A256KW' => EcdhEs,

        'A128GCMKW' => A128GcmKw,
        'A192GCMKW' => A192GcmKw,
        'A256GCMKW' => A256GcmKw,

        'PBES2-HS256+A128KW' => Pbes2Hs256A128Kw,
        'PBES2-HS384+A192KW' => Pbes2Hs384A192Kw,
        'PBES2-HS512+A256KW' => Pbes2Hs512A256Kw
      }.freeze

      class << self
        def for(name)
          KNOWN_ALGS[name]
        end
      end
    end
  end
end

require 'jwa/algorithms/content_encryption/a128_cbc_hs256'
require 'jwa/algorithms/content_encryption/a192_cbc_hs384'
require 'jwa/algorithms/content_encryption/a256_cbc_hs512'

require 'jwa/algorithms/content_encryption/a128_gcm'
require 'jwa/algorithms/content_encryption/a192_gcm'
require 'jwa/algorithms/content_encryption/a256_gcm'

module JWA
  module Algorithms
    module ContentEncryption
      KNOWN_ENCS = {
        'A128CBC-HS256' => A128CbcHs256,
        'A192CBC-HS384' => A192CbcHs384,
        'A256CBC-HS512' => A256CbcHs512,

        'A128GCM' => A128Gcm,
        'A192GCM' => A192Gcm,
        'A256GCM' => A256Gcm
      }.freeze

      class << self
        def for(name)
          KNOWN_ENCS[name]
        end
      end
    end
  end
end

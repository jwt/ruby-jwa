module JWA
  module Algorithms
    module KeyManagement
      class A192GcmKw
        def initialize(key, iv)
          @key = key
          @iv = iv
        end

        def encrypt(plaintext)
          cipher = A192gcm.new(@key, @iv)
          cipher.encrypt(plaintext, '')
        end

        def decrypt(ciphertext, tag)
          cipher = A192gcm.new(@key, @iv)
          cipher.decrypt(ciphertext, '', tag)
        end
      end
    end
  end
end

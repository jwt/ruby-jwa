module JWA
  module Algorithms
    module KeyManagement
      module AesGcmKw
        def initialize(key, iv)
          @key = key
          @iv = iv
        end

        def encrypt(plaintext)
          cipher = self.class.cipher.new(@key, @iv)
          cipher.encrypt(plaintext, '')
        end

        def decrypt(ciphertext, tag)
          cipher = self.class.cipher.new(@key, @iv)
          cipher.decrypt(ciphertext, '', tag)
        end
      end
    end
  end
end

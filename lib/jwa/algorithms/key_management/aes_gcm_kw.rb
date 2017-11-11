module JWA
  module Algorithms
    module KeyManagement
      module AesGcmKw
        def initialize(key, iv = nil)
          @key = key
          @iv = iv

          if @key.length != self.class.key_length
            raise ArgumentError, "Invalid Key. Expected length: #{self.class.key_length}. Actual: #{@key.length}."
          end
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

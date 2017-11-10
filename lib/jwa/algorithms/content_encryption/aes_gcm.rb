require 'jwa/cipher'

module JWA
  module Algorithms
    module ContentEncryption
      # Abstract AES in Galois Counter mode for different key sizes.
      module AesGcm
        attr_reader :key, :iv

        def initialize(key, iv = nil)
          @key = key
          @iv = iv || SecureRandom.random_bytes(12)

          if @key.length != self.class.key_length
            raise JWA::InvalidKey, "Invalid Key. Expected length: #{self.class.key_length}. Actual: #{@key.length}."
          end

          if @iv.length != 12
            raise JWA::InvalidIV, "Invalid IV. Expected length: 16. Actual: #{@iv.length}."
          end
        end

        def encrypt(plaintext, authenticated_data)
          setup_cipher(:encrypt, authenticated_data)
          ciphertext = cipher.update(plaintext) + cipher.final

          [ciphertext, cipher.auth_tag]
        end

        def decrypt(ciphertext, authenticated_data, tag)
          setup_cipher(:decrypt, authenticated_data, tag)
          cipher.update(ciphertext) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          raise JWA::BadDecrypt, 'Invalid ciphertext or authentication tag'
        end

        def setup_cipher(direction, auth_data, tag = nil)
          cipher.send(direction)
          cipher.key = @key
          cipher.iv = @iv
          cipher.auth_tag = tag if tag
          cipher.auth_data = auth_data
        end

        def cipher
          @cipher ||= Cipher.for(self.class.cipher_name)
        end

        def self.included(base)
          base.extend(ClassMethods)
        end

        module ClassMethods
          def available?
            Cipher.for(cipher_name)
            true
          rescue NotImplementedError
            false
          end
        end
      end
    end
  end
end

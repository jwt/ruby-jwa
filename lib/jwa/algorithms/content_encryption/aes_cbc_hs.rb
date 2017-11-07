require 'jwa/cipher'

module JWA
  module Algorithms
    module ContentEncryption
      # Abstract AES in CBC mode, with SHA2 signature for different key sizes.
      module AesCbcHs
        attr_reader :key, :iv

        def initialize(key, iv = nil)
          @key = key
          @iv = iv || SecureRandom.random_bytes(16)

          if @key.length != self.class.key_length
            raise JWA::InvalidKey, "Invalid Key. Expected length: #{self.class.key_length}. Actual: #{@key.length}."
          end

          if @iv.length != 16
            raise JWA::InvalidIV, "Invalid IV. Expected length: 16. Actual: #{@iv.length}."
          end
        end

        def encrypt(plaintext, authenticated_data)
          ciphertext = cipher_round(:encrypt, plaintext)
          signature = generate_tag(authenticated_data, ciphertext)

          [ciphertext, signature]
        end

        def decrypt(ciphertext, authenticated_data, tag)
          signature = generate_tag(authenticated_data, ciphertext)
          if signature != tag
            raise JWA::BadDecrypt, 'Signature check failed. The AAD may have been tampered.'
          end

          cipher_round(:decrypt, ciphertext)
        rescue OpenSSL::Cipher::CipherError
          raise JWA::BadDecrypt, 'Invalid ciphertext or authentication tag.'
        end

        def cipher_round(direction, data)
          cipher.send(direction)
          cipher.key = enc_key
          cipher.iv = @iv

          cipher.update(data) + cipher.final
        end

        def generate_tag(authenticated_data, ciphertext)
          length = [authenticated_data.length * 8].pack('Q>') # 64bit big endian

          to_sign = authenticated_data + @iv + ciphertext + length
          signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new(self.class.hash_name), mac_key, to_sign)

          signature[0...mac_key.length]
        end

        def mac_key
          @key[0...self.class.key_length / 2]
        end

        def enc_key
          @key[self.class.key_length / 2..-1]
        end

        def cipher
          @cipher ||= Cipher.for(self.class.cipher_name)
        end

        def self.included(base)
          base.extend(ClassMethods)
        end

        # Provides availability checks for Key Encryption algorithms
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

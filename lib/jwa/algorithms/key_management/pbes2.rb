module JWA
  module Algorithms
    module KeyManagement
      module Pbes2
        def initialize(password, salt, iterations)
          salt = "#{self.class.alg_name}\x00#{salt}"

          @key = kdf.run(password, salt, iterations, self.class.key_length)
        end

        def encrypt(plaintext)
          self.class.kw_class.new(@key).encrypt(plaintext)
        end

        def decrypt(ciphertext)
          self.class.kw_class.new(@key).decrypt(ciphertext)
        end

        private

        def kdf
          @_kdf ||= Support::PBKDF2.new(OpenSSL::Digest::SHA256.new)
        end
      end
    end
  end
end

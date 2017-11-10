module JWA
  module Algorithms
    module KeyManagement
      module Pbes2
        def initialize(password, salt, iterations)
          @password = password
          @salt = "#{self.class.alg_name}\x00#{salt}"
          @iterations = iterations
        end

        def encrypt(plaintext)
          pbkdf2 = Support::PBKDF2.new(OpenSSL::Digest::SHA256.new)
          key = pbkdf2.run(@password, @salt, @iterations, self.class.key_length)

          self.class.kw_class.new(key).encrypt(plaintext)
        end

        def decrypt(ciphertext)
          pbkdf2 = Support::PBKDF2.new(OpenSSL::Digest::SHA256.new)
          key = pbkdf2.run(@password, @salt, @iterations, self.class.key_length)

          self.class.kw_class.new(key).decrypt(ciphertext)
        end
      end
    end
  end
end

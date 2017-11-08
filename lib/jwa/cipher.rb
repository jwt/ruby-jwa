module JWA
  # Helper to get OpenSSL cipher instance from a string.
  module Cipher
    class << self
      # Ruby raises RuntimeError
      # jRuby raises OpenSSL::Cipher::CipherError
      # Also jRuby is sligthly more relaxed on cipher names, returning something
      # even for aes-999-cbc, I don't know what it is and how it works.

      def for(cipher_name)
        OpenSSL::Cipher.new(cipher_name)
      rescue RuntimeError, OpenSSL::Cipher::CipherError
        raise NotImplementedError, "The OpenSSL library provided by this Ruby version does not support #{cipher_name}."
      end
    end
  end
end

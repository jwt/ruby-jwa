module JWA
  # Helper to get OpenSSL cipher instance from a string.
  module Cipher
    class << self
      def for(cipher_name)
        OpenSSL::Cipher.new(cipher_name)
      rescue RuntimeError
        raise NotImplementedError, "The OpenSSL library provided by this Ruby version does not support #{cipher_name}."
      end
    end
  end
end

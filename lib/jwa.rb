require 'base64'
require 'json'
require 'jwk'
require 'openssl'
require 'securerandom'

require 'jwa/algorithms'
require 'jwa/cipher'
require 'jwa/version'

module JWA
  class InvalidKey < StandardError; end
  class InvalidIV < StandardError; end
  class BadDecrypt < StandardError; end
end

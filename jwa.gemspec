# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'jwa/version'

Gem::Specification.new do |spec|
  spec.name          = "jwa"
  spec.version       = JWA::VERSION
  spec.authors       = ["Francesco Boffa"]
  spec.email         = ["fra.boffa@gmail.com"]

  spec.summary       = 'JSON Web Algorithms implementation in Ruby'
  spec.description   = 'A Ruby implementation of the RFC 7518 JSON Web Algorithms (JWA) standard'
  spec.homepage      = "https://github.com/jwt/ruby-jwa"
  spec.license       = "MIT"

  spec.files = `git ls-files`.split("\n")
  spec.require_paths = ["lib"]

  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'codeclimate-test-reporter'
end

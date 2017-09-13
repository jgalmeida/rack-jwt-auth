# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rack/jwt/auth/version'

Gem::Specification.new do |spec|
  spec.name          = "rack-jwt-auth"
  spec.version       = Rack::Jwt::Auth::VERSION
  spec.authors       = ["João Almeida"]
  spec.email         = ["jg.almeida56@gmail.com"]
  spec.summary       = %q{Rack jwt auth middleware}
  spec.description   = %q{Rack jwt auth middleware}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt", "~> 2.0"

  spec.add_development_dependency "bundler",   "~> 1.3"
  spec.add_development_dependency "rake",      "~> 10.3"
  spec.add_development_dependency "rspec",     "~> 3.1"
  spec.add_development_dependency "rack-test", "~> 0.6"
end

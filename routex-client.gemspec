# frozen_string_literal: true

require_relative "lib/routex/version"

Gem::Specification.new do |spec|
  spec.name = "routex-client"
  spec.version = Routex::VERSION
  spec.authors = ["Michael Vogl"]

  spec.summary = "Ruby client for YAXI's Open Banking services"
  spec.description = "Port of routex-client-kotlin, including TEE key settlement " \
                     "and SEV-SNP attestation verification. Draft; see PORTING.md."
  spec.homepage = "https://github.com/cubasepp/routex-client-ruby"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir["lib/**/*.rb", "lib/routex/certs/*.pem", "*.md", "LICENSE"]
  spec.require_paths = ["lib"]

  spec.add_dependency "base64", "~> 0.2"
  spec.add_dependency "openssl", "~> 3.0"
end

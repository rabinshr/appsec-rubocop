lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rubocop/bcsecurity/version'

Gem::Specification.new do |spec|
  spec.name        = 'appsec-rubocop-poc'
  spec.version     = RuboCop::BcSecurity::VERSION
  spec.summary     = 'Extra lints to keep us safe :)'
  spec.description = 'A test/proof-of-concept for using RuboCop to prevent regression on some security bugs'
  spec.authors     = ['Evan Johnson']
  spec.email       = 'evan.johnson@bigcommerce.com'
  spec.files       = Dir['README.md', 'config/**/*', 'lib/**/*', 'appsec-rubocop-poc.gemspec']
  spec.homepage    = ''
  spec.license     = ''
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 3.0'

  spec.add_runtime_dependency "rubocop", '>= 1.0'
end

# appsec-rubocop-poc
Proof-of-concept for custom appsec RuboCop lints

## Getting Started

_requires Ruby 3.x and RuboCop_

### Installation

Add the line
```ruby
gem 'appsec-rubocop-poc', git: 'git@github.com:bigcommerce-labs/appsec-rubocop-poc', branch: 'main', require: false
```
to your project's Gemfile then run `bundle install`.

### Using the custom check(s)

Add `- appsec-rubocop-poc` under `require:` at the top of your `.rubocop.yml`.
The following custom checks are enabled by default:

- BcSecurity/LoggingRawPost

Available checks:

- BcSecurity/LoggingRawPost

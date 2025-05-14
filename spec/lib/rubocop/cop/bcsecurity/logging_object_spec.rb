# frozen_string_literal: true

RSpec.describe RuboCop::Cop::BcSecurity::LoggingObject, :config do
  let(:message) { ::RuboCop::Cop::BcSecurity::LoggingObject::MSG }
  subject(:cop) { described_class.new(config) }
  let(:json_object) { { password: 'secret' } }
  let(:source) do
    <<~RUBY
      Rails.logger.warn("#{json_object.to_json} rabin")
    RUBY
  end

  it 'registers offense for interpolated string with hash.to_json in Rails.logger' do
    expect_offense(<<~RUBY)
      Rails.logger.warn("test \#{json_object.to_json} string")
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'registers offense for hash.to_json in Rails.logger' do
    expect_offense(<<~RUBY)
      Rails.logger.warn({key: 'value'}.to_json)
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'registers offense for interpolated string with hash.inspect in Rails.logger' do
    expect_offense(<<~RUBY)
      Rails.logger.warn("test \#{json_object.inspect} string")
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'registers offense for hash.inspect in Rails.logger' do
    expect_offense(<<~RUBY)
      Rails.logger.warn({key:'value'}.inspect)
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'does not register offense for regular string in Rails.logger' do
    expect_no_offenses(<<~RUBY)
      Rails.logger.debug('some text')
    RUBY
  end
end

# frozen_string_literal: true

RSpec.describe RuboCop::Cop::BcSecurity::LoggingRawPost, :config do
  describe 'dangerous logging' do
    it 'registers offense when `raw_post` is an argument to Rails.logger.info' do
      expect_offense(<<~RUBY)
        Rails.logger.info("some text", raw_post)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{RuboCop::Cop::BcSecurity::LoggingRawPost::MSG}
      RUBY
    end

    it 'registers offense when `raw_post` is an argument to Rails.logger.warn' do
      expect_offense(<<~RUBY)
        Rails.logger.warn("some text", other_var, raw_post)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{RuboCop::Cop::BcSecurity::LoggingRawPost::MSG}
      RUBY
    end

    it 'registers offense when `raw_post` is an argument to Rails.logger.error' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some text", raw_post, other_var)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{RuboCop::Cop::BcSecurity::LoggingRawPost::MSG}
      RUBY
    end

    it 'registers offense for `raw_post` in dynamic string passed to Rails.logger method' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some message: \#{raw_post}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{RuboCop::Cop::BcSecurity::LoggingRawPost::MSG}
      RUBY
    end

    it 'detects `@raw_post`' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some message: \#{@raw_post}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{RuboCop::Cop::BcSecurity::LoggingRawPost::MSG}
      RUBY
    end

    it 'detects `request.raw_post`' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some message: \#{request.raw_post}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{RuboCop::Cop::BcSecurity::LoggingRawPost::MSG}
      RUBY
    end

    it 'detects `raw_post.to_json`' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some message: \#{raw_post.to_json}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{RuboCop::Cop::BcSecurity::LoggingRawPost::MSG}
      RUBY
    end
  end
end

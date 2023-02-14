# frozen_string_literal: true

RSpec.describe RuboCop::Cop::BcSecurity::LoggingRawPost, :config do
  describe 'dangerous logging' do
    let(:message) { ::RuboCop::Cop::BcSecurity::LoggingRawPost::MSG }
    let(:sink_message) { format(::RuboCop::Cop::BcSecurity::LoggingRawPost::SINK_MSG, name: 'message') }

    it 'registers offense when `raw_post` is an argument to Rails.logger.info' do
      expect_offense(<<~RUBY)
        Rails.logger.info("some text", raw_post)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
      RUBY
    end

    it 'registers offense when `raw_post` is an argument to Rails.logger.warn' do
      expect_offense(<<~RUBY)
        Rails.logger.warn("some text", other_var, raw_post)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
      RUBY
    end

    it 'registers offense when `raw_post` is an argument to Rails.logger.error' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some text", raw_post, other_var)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
      RUBY
    end

    it 'registers offense for `raw_post` in dynamic string passed to Rails.logger method' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some message: \#{raw_post}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
      RUBY
    end

    it 'detects `@raw_post`' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some message: \#{@raw_post}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
      RUBY
    end

    it 'detects `request.raw_post`' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some message: \#{request.raw_post}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
      RUBY
    end

    it 'detects `raw_post.to_json`' do
      expect_offense(<<~RUBY)
        Rails.logger.error("some message: \#{raw_post.to_json}")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
      RUBY
    end

    it 'detects messages constructed prior to logging' do
      expect_offense(<<~RUBY)
        def foo
          message = "some message: \#{raw_post}"
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
          Rails.logger.info(message, other)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{sink_message}
        end
      RUBY
    end

    it 'detects real example using `log_from' do
      expect_offense(<<~RUBY)
        log_from(
        ^^^^^^^^^ #{message}
          method: __method__,
          status: :error,
          msg: "Receive notification with invalid gateway or profile: raw post=\#{raw_post}",
          data: { store_id: store_id, gateway: gateway }
        )
      RUBY
    end

    it 'detects real example constructing message and passing it to a logging call' do
      expect_offense(<<~RUBY)
        def perform(notification_request)
          store_id, gateway, raw_post = notification_request.values_at(:store_id, :gateway, :raw_post)
          raise(BigCommerce::Error::Invalid, 'Invalid gateway') if gateway.blank?
          raise(BigCommerce::Error::Invalid, 'Invalid raw_post') if raw_post.blank?

          message = "[\#{gateway}_webhooks] Starting notification process for store: \#{store_id}, (raw_post: \#{raw_post})"
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
          Rails.logger.info(message, gateway: gateway, store_id: store_id)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{sink_message}
          BigPay::Payments::Notification::Processor::StripeUpe::StripeUpeNotificationProcessor.new(store_id, gateway, nil, raw_post).process_notification
          message = "[\#{gateway}_webhooks] Finish notification process for store: \#{store_id}, (raw_post: \#{raw_post})"
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
          Rails.logger.info(message, gateway: gateway, store_id: store_id)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{sink_message}
        rescue => e
          Rails.logger.error("[\#{gateway}_webhooks] Error while processing notification for store: \#{store_id}", gateway: gateway, store_id: store_id, message: e.message)
          raise e
        end
      RUBY
    end

    it 'permits dynamic string construction for signature checks' do
      expect_no_offenses(<<~RUBY)
        def parse_authentication_header(x_affirm_signature_multi)
          timestamp, hashed_payload = x_affirm_signature_multi.split(',')
          hashed_payload_keys = hashed_payload.gsub(/v0=/, '').split('=')
          timestamp = timestamp.gsub(/t=/, '')
          return nil unless validate_timestamp(timestamp.to_i)

          payload = "\#{timestamp}.\#{@request.raw_post}"

          [payload, hashed_payload_keys]
        end
      RUBY
    end
  end
end

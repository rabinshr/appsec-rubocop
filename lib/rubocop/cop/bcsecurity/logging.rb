module RuboCop
  module Cop
    module BcSecurity
      # matches instances where `raw_post` values are formatted directly into log messages
      # Reason: We recently removed nearly 50 instances of this from BigPay.
      class LoggingRawPost < RuboCop::Cop::Base
        def_node_matcher :logs_raw_post, <<~PATTERN
          (send
            (send
              (const nil? :Rails) :logger) $_
            <`({send | ivar} ... {:raw_post | :@raw_post}) ...>)
        PATTERN

        MSG = 'You appear to be logging raw POST data, this could result in logging secret values.'

        def on_send(node)
          logs_raw_post(node) do |_|
            add_offense(node)
          end
        end
      end
    end
  end
end

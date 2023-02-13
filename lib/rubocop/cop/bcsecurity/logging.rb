# frozen_string_literal: true

module RuboCop
  module Cop
    module BcSecurity
      # matches instances where `raw_post` values are formatted directly into log messages
      # Reason: We recently removed nearly 50 instances of this from BigPay.
      class LoggingRawPost < RuboCop::Cop::Base
        def_node_matcher :logs_raw_post, <<~PATTERN
          {(send
            (send
              (const nil? :Rails) :logger) _
            <`({send | ivar} ... {:raw_post | :@raw_post}) ...>) | (send nil? :log_from <`{:raw_post | :@raw_post} ...>)}
        PATTERN

        def_node_matcher :dangerous_string_assign, <<~PATTERN
          (lvasgn $_
              <`{:raw_post | :@raw_post} ...>)
        PATTERN

        def_node_matcher :logs_name, <<~PATTERN
          {(send (send (const nil? :Rails) :logger) _ <`%name ...>) | (send const nil? :log_from <`%name ...>)}
        PATTERN

        MSG = 'You appear to be logging raw POST data, this could result in logging secret values.'

        def on_send(node)
          logs_raw_post(node) do |_|
            add_offense(node)
          end
        end

        def on_begin(node)
          dangerous_names = {'raw_post'=>nil, '@raw_post'=>nil}
          node.each_child_node do |child|
            if child.lvasgn_type?
              dangerous_string_assign(child) do |name|
                dangerous_names[name.to_sym] = child
              end
            else
              mark_offenses(child, dangerous_names)
            end
          end
        end

        def mark_offenses(node, names)
          names.each do |name, source_node|
            if logs_name(node, :name=>name)
              if !source_node
                add_offense(node)
              else
                add_offense(source_node)
                add_offense(node, message: format("`%<name>s` passed to logging call here.", name: name))
              end
            end
          end
        end
      end
    end
  end
end

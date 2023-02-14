# frozen_string_literal: true

module RuboCop
  module Cop
    module BcSecurity
      ##
      # RuboCop for instances where `raw_post` values are formatted into log messages
      # Reason: We recently removed over 50 instances of this from BigPay.
      class LoggingRawPost < RuboCop::Cop::Base
        MSG = 'You appear to be logging raw POST data, this could result in logging secret values.'
        SINK_MSG = '`%<name>s` passed to logging call here.'
        POST_NAMES = [:raw_post, :@raw_post]

        ##
        # defines a matcher for assignment of a dynamic string built with raw POST data to a variable
        # ex. `dangerous_string_assign(node)` matches code like `message = "raw post: #{context.raw_post}"`
        def_node_matcher :dangerous_string_assign, <<~PATTERN
          (lvasgn $_
              (dstr <`{:raw_post | :@raw_post} ...>))
        PATTERN

        ##
        # defines a matcher for logging calls that receive a given variable/name via their arguments
        # ex. `logs_name(node, :message)` would match code like `Rails.logger.info(message, extra_data)`
        def_node_matcher :logs_name, <<~PATTERN
          {(send (send (const nil? :Rails) :logger) _ <`%1 ...>) | (send nil? :log_from <`%1 ...>)}
        PATTERN

        ##
        # called for each `send` node in the AST
        # (TODO: This could possibly be made redundant with some work on the check below.)
        # @param [Node] node a `send` AST node
        def on_send(node)
          mark_direct_offenses(node, POST_NAMES)
        end

        ##
        # called for each `begin` node (covers most cases with multi-line blocks of code)
        # @param [Node] node a `begin` AST node
        def on_begin(node)
          dangerous_names = {}
          node.each_child_node do |child|
            # collect names of variables if the match our dangerous assignment pattern
            if child.lvasgn_type?
              dangerous_string_assign(child) do |name|
                dangerous_names[name] = child
              end
            else
              mark_split_offenses(child, dangerous_names)
            end
          end
        end

        ##
        # add RuboCop offenses for cases where raw POST data is seen in a child of the
        # node representing the logging call
        # @param [Node] node an AST node
        # @param [Array] names symbolized names that should not be passed to logging methods
        def mark_direct_offenses(node, names)
          names.each do |name|
            if logs_name(node, name)
              add_offense(node)
              # no need to register more than 1 offense per line
              break
            end
          end
        end

        ##
        # add RuboCop offenses for cases where the 'source' and 'sink' for logging raw POST
        # data are different nodes (such as when it's formatted into a string variable,
        # then that variable is later passed to a logging method)
        # @param [Node] node an AST node
        # @param [Array] names symbolized names that should not be passed to logging methods
        def mark_split_offenses(node, names)
          names.each do |name, source_node|
            if logs_name(node, name)
              add_offense(source_node)
              add_offense(node, message: format(SINK_MSG, name: name))
            end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module RuboCop
  module Cop
    module BcSecurity
      # This cop checks for raw JSON or JSON objects being passed to Rails.logger calls.
      #
      # Bad:
      #   Rails.logger.info({ key: 'value' }.to_json)
      #   Rails.logger.debug(json_object)
      #   Rails.logger.fatal("#{hash_object.inspect}")
      #   Rails.logger.info("#{hash_object.to_json}")
      #
      # Good:
      #   Rails.logger.info('A descriptive log message')
      class LoggingObject < RuboCop::Cop::Base
        MSG = 'Avoid logging string version of objects, this could result in logging sensitive data.'
        MATCHER_NAMES = %i[inspect to_json to_s].freeze

        ##
        # defines a matcher for logging calls that receive a string as their argument
        def_node_matcher :log_match?, <<~PATTERN
          {(send (send (const nil? :Rails) :logger) _ <`%1 ...>)}
        PATTERN

        ##
        # called for each `send` node in the AST
        # @param [Node] node a `send` AST node
        def on_send(node)
          mark_direct_offenses(node, MATCHER_NAMES)
        end

        def mark_direct_offenses(node, names)
          names.each do |name|
            next unless log_match?(node, name)

            add_offense(node)
          end
        end
      end
    end
  end
end

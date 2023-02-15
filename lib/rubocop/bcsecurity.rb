# frozen_string_literal: true

module RuboCop
  module BcSecurity
    PROJECT_ROOT   = Pathname.new(__dir__).parent.parent.expand_path
    CONFIG_DEFAULT = PROJECT_ROOT.join('config', 'default.yml')
    CONFIG = YAML.safe_load(CONFIG_DEFAULT.read)

    private_constant(:CONFIG_DEFAULT, :PROJECT_ROOT)
  end
end

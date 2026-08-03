# frozen_string_literal: true

# Deployment helper for the identity contracts.
#
# Wraps forge, cast and gh so that deploying, inspecting and wiring up a deployment is a single
# command each, with the addresses and endpoints remembered between runs instead of being retyped
# as environment variables.
module Identity
  VERSION = "0.1.0"

  # Base for every failure this tool raises deliberately. Anything else escaping is a bug.
  Error = Class.new(StandardError)

  # A tool, credential or configuration value the command needs is absent.
  MissingRequirement = Class.new(Error)

  # An external command exited non-zero.
  CommandFailed = Class.new(Error)

  # The user asked for something the current state cannot satisfy.
  InvalidState = Class.new(Error)
end

require_relative "identity/ui"
require_relative "identity/shell"
require_relative "identity/config"
require_relative "identity/chain"
require_relative "identity/github"
require_relative "identity/deployment"
require_relative "identity/cli"

# frozen_string_literal: true

require "optparse"

module Identity
  # Argument parsing and dispatch. Every command is one method on {Deployment}; this layer only
  # turns argv into that call and turns a raised {Error} into an exit status.
  class CLI
    USAGE = <<~TEXT
      identity — deployment helper for the identity contracts

      Usage: identity <command> [options]

      Commands:
        doctor                     check tooling, credentials and the recorded deployment
        deploy                     deploy the verifier and UIK, then record them
        status                     compare the deployment against this repository and the JWKS
        configure                  push the recorded values into repository variables and secrets
        keys sync                  mirror GitHub's signing keys into the verifier

      Options:
        --rpc-url URL              RPC endpoint (deploy; remembered afterwards)
        --key-sync-key KEY         verifier owner key, stored as the key sync secret
        --registrar-key KEY        gas-paying key, stored as the registrar secret
        --dry-run                  report the plan without writing anything (configure, keys sync)
        --no-revoke                keep keys GitHub no longer publishes (keys sync)
        -h, --help                 this message
        -v, --version              version

      The deployer key is read from IDENTITY_PRIVATE_KEY or PRIVATE_KEY, or prompted for.
      It is never written to #{Config::FILENAME}.
    TEXT

    def initialize(argv, root: Dir.pwd)
      @argv = argv.dup
      @root = root
      @options = { revoke_stale: true, dry_run: false }
    end

    def run
      command = parse!
      if command.nil?
        puts USAGE
        return 0
      end

      dispatch(command)
      0
    rescue Error => e
      UI.error e.message
      1
    rescue Interrupt
      UI.error "interrupted"
      130
    end

    private

    attr_reader :argv, :root, :options

    def parse!
      parser.parse!(argv)
      argv.shift
    end

    def parser
      OptionParser.new do |o|
        o.on("--rpc-url URL") { |value| options[:rpc_url] = value }
        o.on("--key-sync-key KEY") { |value| options[:key_sync_key] = value }
        o.on("--registrar-key KEY") { |value| options[:registrar_key] = value }
        o.on("--dry-run") { options[:dry_run] = true }
        o.on("--no-revoke") { options[:revoke_stale] = false }
        o.on("-h", "--help") do
          puts USAGE
          exit 0
        end
        o.on("-v", "--version") do
          puts VERSION
          exit 0
        end
      end
    end

    def dispatch(command)
      deployment = Deployment.new(root: root)

      case command
      when "doctor" then deployment.doctor
      when "deploy" then deployment.deploy(rpc_url: options[:rpc_url])
      when "status" then deployment.status
      when "configure"
        deployment.configure(key_sync_key: options[:key_sync_key], registrar_key: options[:registrar_key],
                             dry_run: options[:dry_run])
      when "keys" then keys(deployment)
      else
        raise Error, "unknown command: #{command}"
      end
    end

    def keys(deployment)
      subcommand = argv.shift
      raise Error, "unknown keys subcommand: #{subcommand.inspect}" unless subcommand == "sync"

      deployment.sync_keys(dry_run: options[:dry_run], revoke_stale: options[:revoke_stale])
    end
  end
end

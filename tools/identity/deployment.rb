# frozen_string_literal: true

require "net/http"
require "uri"

module Identity
  # The work behind each command. Holds the wiring between the config file, the chain and the
  # repository so the CLI layer stays a thin dispatcher.
  class Deployment
    ISSUER = "https://token.actions.githubusercontent.com"

    VERIFIER_SCRIPT = "DeployGithubOidcVerifier.s.sol"
    UIK_SCRIPT = "DeployUIK.s.sol"

    VARIABLES = {
      "FCF_VERIFIER_ADDRESS" => :verifier,
      "FCF_UIK_ADDRESS" => :uik,
      "FCF_RPC_URL" => :rpc_url,
      "FCF_VERIFIER_FROM_BLOCK" => :deployed_at,
      "FCF_RELAYER_URL" => :relayer_url
    }.freeze

    KEY_SYNC_SECRET = "FCF_KEY_SYNC_PRIVATE_KEY"

    def initialize(root: Dir.pwd)
      @root = root
      @config = Config.load(root)
      @github = GitHub.new(root: root)
    end

    # --- commands -----------------------------------------------------------

    def doctor
      UI.heading "Tooling"
      %w[forge cast gh].each do |tool|
        Shell.available?(tool) ? UI.ok(tool) : UI.error("#{tool} is not on PATH")
      end

      UI.heading "GitHub"
      if !GitHub.available?
        UI.error "gh is not on PATH"
      elsif !github.authenticated?
        UI.error "gh is not authenticated; run gh auth login"
      else
        UI.ok "authenticated"
        begin
          repo = github.repo
          UI.field "repository", repo.slug
          UI.field "database id", repo.database_id
          UI.field "workflow ref", repo.job_workflow_ref
        rescue Error => e
          UI.error "could not resolve the repository: #{e.message.lines.first.strip}"
          UI.note "the checkout needs a GitHub remote before deploying"
        end
      end

      UI.heading "Chain"
      if config.rpc_url.to_s.empty?
        UI.warn "no RPC configured; pass --rpc-url to deploy"
      elsif chain.reachable?
        UI.ok "#{config.rpc_url} (chain #{chain.chain_id})"
      else
        UI.error "#{config.rpc_url} is unreachable"
      end

      UI.heading "Deployment"
      config.deployed? ? UI.ok("recorded in #{Config::FILENAME}") : UI.warn("nothing deployed yet")
      nil
    end

    def deploy(rpc_url: nil, relayer_url: nil)
      Shell.require_tools!("forge", "cast", "gh")

      config.rpc_url = rpc_url if rpc_url
      config.relayer_url = relayer_url if relayer_url
      raise MissingRequirement, "no RPC URL; pass --rpc-url" if config.rpc_url.to_s.empty?
      raise InvalidState, "#{config.rpc_url} is unreachable" unless chain.reachable?

      repo = github.repo
      deployer = chain.address_of(private_key)

      UI.heading "Plan"
      UI.field "chain", chain.chain_id
      UI.field "deployer", deployer
      UI.field "balance", "#{chain.balance_eth(deployer)} ETH"
      UI.field "attestation repo", "#{repo.slug} (#{repo.database_id})"
      UI.field "workflow ref", repo.job_workflow_ref
      raise InvalidState, "deployer has no balance" if chain.balance(deployer).zero?
      raise InvalidState, "cancelled" unless UI.confirm?("\nDeploy?")

      UI.heading "Deploying"
      UI.step "GithubOidcVerifier"
      verifier = expect_contract(chain.run_script(VERIFIER_SCRIPT, env: {}, private_key: private_key),
                                 "GithubOidcVerifier")
      UI.ok "#{verifier.address} (block #{verifier.block})"

      UI.step "UIK"
      uik = expect_contract(
        chain.run_script(
          UIK_SCRIPT,
          env: {
            "JWT_VERIFIER_ADDRESS" => verifier.address,
            "ATTESTATION_REPO_ID" => repo.database_id,
            "JOB_WORKFLOW_REF" => repo.job_workflow_ref
          },
          private_key: private_key
        ),
        "UIK"
      )
      UI.ok "#{uik.address} (block #{uik.block})"

      config.chain_id = chain.chain_id
      config.verifier = verifier.address
      config.uik = uik.address
      config.deployed_at = verifier.block
      config.attestation_repo_id = repo.database_id
      config.job_workflow_ref = repo.job_workflow_ref
      config.save

      UI.heading "Saved"
      UI.note "#{Config::FILENAME} updated. Next: identity configure, then identity keys sync."
      nil
    end

    def status
      require_deployment!

      UI.heading "Recorded"
      UI.field "chain", config.chain_id
      UI.field "rpc", config.rpc_url
      UI.field "verifier", config.verifier
      UI.field "uik", config.uik
      UI.field "from block", config.deployed_at

      UI.heading "On chain"
      unless chain.reachable?
        UI.error "#{config.rpc_url} is unreachable"
        return
      end

      UI.field "verifier owner", chain.call(config.verifier, "owner()(address)")
      UI.field "uik owner", chain.call(config.uik, "owner()(address)")
      UI.field "renderer", renderer_description
      UI.field "renderer frozen", chain.call(config.uik, "rendererFrozen()(bool)")

      UI.heading "Attestation source"
      compare "repository id", chain.call_integer(config.uik, "attestationRepoId()(uint64)"),
              github.repo.database_id
      compare "workflow ref", chain.call_string(config.uik, "jobWorkflowRef()(string)"),
              github.repo.job_workflow_ref

      UI.heading "Signing keys"
      report_keys
      nil
    end

    def configure(relayer_url: nil, key_sync_key: nil, dry_run: false)
      require_deployment!
      config.relayer_url = relayer_url if relayer_url

      UI.note "dry run against #{github.repo.slug}, nothing will be written" if dry_run

      UI.heading "Repository variables"
      VARIABLES.each do |name, field|
        value = config.public_send(field)
        if value.to_s.empty?
          UI.warn "#{name} skipped, #{field} is unset"
          next
        end

        github.set_variable(name, value) unless dry_run
        UI.ok "#{name} = #{value}"
      end

      key = key_sync_key || ENV.fetch("FCF_KEY_SYNC_PRIVATE_KEY", nil)
      UI.heading "Repository secrets"
      if key.to_s.empty?
        UI.warn "#{KEY_SYNC_SECRET} skipped; pass --key-sync-key or set it in the environment"
        UI.note "This key can add signing keys, so keep it dedicated to the sync job."
      else
        github.set_secret(KEY_SYNC_SECRET, key) unless dry_run
        UI.ok KEY_SYNC_SECRET
      end

      config.save unless dry_run
      nil
    end

    def sync_keys(dry_run: false, revoke_stale: true)
      require_deployment!

      env = {
        "VERIFIER_ADDRESS" => config.verifier,
        "RPC_URL" => config.rpc_url,
        "FROM_BLOCK" => config.deployed_at,
        "DRY_RUN" => dry_run.to_s,
        "REVOKE_STALE" => revoke_stale.to_s
      }
      env["PRIVATE_KEY"] = private_key unless dry_run

      Shell.stream(File.join(root, "sync-github-keys.sh"), env: env)
      nil
    end

    private

    attr_reader :root, :config, :github

    def chain
      @chain ||= Chain.new(rpc_url: config.rpc_url, root: root)
    end

    # Read once, never written to disk, never echoed.
    def private_key
      @private_key ||= begin
        raw = ENV["IDENTITY_PRIVATE_KEY"] || ENV["PRIVATE_KEY"] || UI.read_secret("Deployer private key")
        raise MissingRequirement, "no private key provided" if raw.to_s.empty?

        raw.start_with?("0x") ? raw : "0x#{raw}"
      end
    end

    def require_deployment!
      return if config.deployed?

      raise InvalidState, "nothing deployed yet; run identity deploy"
    end

    def expect_contract(deployed, name)
      deployed.find { |contract| contract.name == name } ||
        raise(InvalidState, "#{name} was not created by the deploy script")
    end

    def renderer_description
      address = chain.call(config.uik, "renderer()(address)")
      address.match?(/\A0x0+\z/) ? "built-in" : address
    end

    def compare(label, actual, expected)
      if actual == expected
        UI.field label, actual, colour: :green
      else
        UI.field label, "#{actual} (repository says #{expected})", colour: :red
      end
    end

    def report_keys
      published = fetch_jwks_kids
      active = published.count { |kid| key_active?(kid) }
      colour = active == published.size ? :green : :red
      UI.field "published", published.size
      UI.field "active on chain", active, colour: colour
      UI.note "run identity keys sync" unless active == published.size
    rescue StandardError => e
      UI.warn "could not check keys: #{e.message}"
    end

    def key_active?(kid)
      hash = Shell.capture("cast", "keccak", kid, chdir: root)
      chain.call(config.verifier, "keyOf(bytes32)((bytes,bytes,bool))", hash).end_with?("true)")
    end

    def fetch_jwks_kids
      configuration = get_json("#{ISSUER}/.well-known/openid-configuration")
      jwks_uri = configuration.fetch("jwks_uri")
      # The discovery document names its own key endpoint; only ever follow it back to the issuer.
      raise InvalidState, "jwks_uri #{jwks_uri} is outside #{ISSUER}" unless jwks_uri.start_with?("#{ISSUER}/")

      get_json(jwks_uri).fetch("keys").select { |key| key["kty"] == "RSA" }.filter_map { |key| key["kid"] }
    end

    def get_json(url)
      response = Net::HTTP.get_response(URI(url))
      raise InvalidState, "#{url} returned #{response.code}" unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body)
    end
  end
end

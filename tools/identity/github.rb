# frozen_string_literal: true

module Identity
  # The repository side of a deployment, through the gh CLI.
  #
  # Using gh rather than the REST API directly means the operator's existing login is the only
  # credential involved, and there is no token for this tool to store or leak.
  class GitHub
    WORKFLOW_PATH = ".github/workflows/register.yml"

    Repo = Data.define(:slug, :database_id, :default_branch) do
      # The exact `job_workflow_ref` claim the attestation workflow will produce.
      #
      # Assembling this by hand is the easiest way to deploy a UIK that rejects every proof, which
      # is why it is derived from the repository rather than typed in.
      def job_workflow_ref
        "#{slug}/#{WORKFLOW_PATH}@refs/heads/#{default_branch}"
      end
    end

    def self.available?
      Shell.available?("gh")
    end

    def initialize(root: Dir.pwd)
      @root = root
    end

    def authenticated?
      Shell.capture("gh", "auth", "status", chdir: root)
      true
    rescue CommandFailed
      false
    end

    # The numeric repository id is what the contract pins, and `gh repo view` only exposes the
    # GraphQL node id, so this goes through the REST endpoint. `{owner}` and `{repo}` are expanded
    # by gh from the current checkout.
    def repo
      @repo ||= begin
        data = Shell.capture_json("gh", "api", "repos/{owner}/{repo}", chdir: root)
        Repo.new(
          slug: data.fetch("full_name"),
          database_id: data.fetch("id"),
          default_branch: data.fetch("default_branch")
        )
      end
    end

    def set_variable(name, value)
      Shell.capture("gh", "variable", "set", name, "--body", value.to_s, chdir: root)
    end

    def set_secret(name, value)
      Shell.capture("gh", "secret", "set", name, "--body", value.to_s, chdir: root)
    end

    def variables
      Shell.capture_json("gh", "variable", "list", "--json", "name,value", chdir: root)
        .to_h { |entry| [entry.fetch("name"), entry.fetch("value")] }
    rescue CommandFailed
      {}
    end

    def secret_names
      Shell.capture_json("gh", "secret", "list", "--json", "name", chdir: root).map { |entry| entry.fetch("name") }
    rescue CommandFailed
      []
    end

    private

    attr_reader :root
  end
end

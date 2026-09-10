# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require_relative "../identity"

class ConfigTest < Minitest::Test
  def test_verifier_only_record_is_operable
    config = Identity::Config.new(path: "unused")
    refute config.deployed?
    config.verifier = "0x#{'1' * 40}"
    assert config.deployed?
    assert_nil config.uik
  end

  def test_key_sync_matrix_keeps_chains_independent
    workflow = YAML.safe_load_file(File.expand_path("../../.github/workflows/sync-github-keys.yml", __dir__))
    job = workflow.fetch("jobs").fetch("sync")
    strategy = job.fetch("strategy")
    assert_equal false, strategy.fetch("fail-fast")
    assert_equal [8453, 4663], strategy.fetch("matrix").fetch("chain").map { |chain| chain.fetch("id") }
    env = job.fetch("steps").find { |step| step["name"] == "Sync keys" }.fetch("env")
    assert_equal "${{ matrix.chain.id }}", env.fetch("EXPECTED_CHAIN_ID")
    %w[VERIFIER_ADDRESS RPC_URL PRIVATE_KEY FROM_BLOCK].each do |name|
      assert_includes env.fetch(name), "matrix.chain.prefix"
    end
  end

  def test_independent_chain_records_and_github_names
    Dir.mktmpdir do |root|
      base = Identity::Config.load(root)
      base.chain_id = 8453
      base.verifier = "0x#{'1' * 40}"
      base.save
      robinhood = Identity::Config.load(root, filename: ".identity-robinhood.yml")
      assert_nil robinhood.verifier
      robinhood.chain_id = 4663
      robinhood.verifier = "0x#{'2' * 40}"
      robinhood.save
      assert_equal base.verifier, Identity::Config.load(root).verifier
      assert_equal robinhood.verifier, Identity::Config.load(root, filename: ".identity-robinhood.yml").verifier
      assert_equal "FCF_RPC_URL", base.github_name("FCF_RPC_URL")
      assert_equal "FCF_ROBINHOOD_RPC_URL", robinhood.github_name("FCF_RPC_URL")
      assert_equal "FCF_ROBINHOOD_REGISTRAR_PRIVATE_KEY", robinhood.github_name("FCF_REGISTRAR_PRIVATE_KEY")
      robinhood.chain_id = 46630
      assert_raises(Identity::InvalidState) { robinhood.github_name("FCF_RPC_URL") }
    end
  end
end

# frozen_string_literal: true

require "yaml"

module Identity
  # What the tool remembers between runs, kept beside the repository in `.identity.yml`.
  #
  # Deliberately holds no secrets. The deployer key is read from the environment or prompted for on
  # each command that needs it, so this file stays safe to leave lying around.
  class Config
    FILENAME = ".identity.yml"

    FIELDS = %i[
      rpc_url
      chain_id
      verifier
      uik
      deployed_at
      attestation_repo_id
      job_workflow_ref
    ].freeze

    attr_accessor(*FIELDS)
    attr_reader :path

    def self.load(root)
      path = File.join(root, FILENAME)
      stored = File.exist?(path) ? YAML.safe_load_file(path) || {} : {}
      new(path: path, **stored.transform_keys(&:to_sym).slice(*FIELDS))
    end

    def initialize(path:, **values)
      @path = path
      FIELDS.each { |field| instance_variable_set(:"@#{field}", values[field]) }
    end

    def save
      File.write(path, +"# Written by bin/identity. Safe to commit only if the endpoints are public.\n" << to_yaml)
      self
    end

    def deployed?
      !verifier.to_s.empty? && !uik.to_s.empty?
    end

    def to_h
      FIELDS.to_h { |field| [field.to_s, public_send(field)] }.compact
    end

    def to_yaml
      to_h.to_yaml.sub(/\A---\n/, "")
    end
  end
end

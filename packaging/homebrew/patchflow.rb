class Patchflow < Formula
  desc "Local-first security scanner for code, dependencies, and secrets"
  homepage "https://patchflow.dev"
  url "https://github.com/patchflow/patchflow-cli/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "Apache-2.0"
  version "0.1.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w \
      -X github.com/patchflow/patchflow-cli/pkg/version.Version=#{version} \
      -X github.com/patchflow/patchflow-cli/pkg/version.Commit=brew \
      -X github.com/patchflow/patchflow-cli/pkg/version.Date=#{Time.now.utc.iso8601}")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/patchflow version")
  end
end

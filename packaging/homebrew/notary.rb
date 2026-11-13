# Homebrew formula for Notary.
# Rendered by sync.py; @VERSION@ and the @SHA256_*@ values are filled in by the
# release workflow (job "publish", step "Render package-manager manifests") and
# shipped in notary-<version>-package-manifests.tar.gz. Copy the rendered file
# into the tap repository (LLCForge/homebrew-tap, Formula/notary.rb).
class Notary < Formula
  desc "RPKI Route Origin Validation checker with RTR client, watch daemon and query API"
  homepage "https://github.com/LLCForge/Notary"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/LLCForge/Notary/releases/download/v@VERSION@/notary-@VERSION@-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/LLCForge/Notary/releases/download/v@VERSION@/notary-@VERSION@-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/LLCForge/Notary/releases/download/v@VERSION@/notary-@VERSION@-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/LLCForge/Notary/releases/download/v@VERSION@/notary-@VERSION@-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_LINUX_MUSL@"
    end
  end

  def install
    bin.install "notary"
    pkgetc.install "notary.example.toml" if File.exist?("notary.example.toml")
    doc.install Dir["README*.md"]
  end

  service do
    run [opt_bin/"notary", "run", "--config", etc/"notary/notary.toml"]
    environment_variables STATE_DIRECTORY: var/"lib/notary"
    keep_alive successful_exit: false
    log_path var/"log/notary.log"
    error_log_path var/"log/notary.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/notary --version")
  end
end

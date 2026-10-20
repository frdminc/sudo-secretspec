# typed: strict
# frozen_string_literal: true

# Homebrew package for the upstream engine and downstream opt-in companion.
class SudoSecretspec < Formula
  desc "SecretSpec engine with an opt-in macOS privilege-boundary companion"
  homepage "https://github.com/frdminc/sudo-secretspec"
  url "https://github.com/frdminc/sudo-secretspec/archive/refs/tags/v0.19.1-sudo.29.tar.gz"
  # Homebrew parses the trailing ".1" of the tag as the whole version, which
  # breaks upgrade detection. State it explicitly.
  version "0.19.1-sudo.29"
  sha256 "54167f77fc5d9887610b2b13a62df69efdcb4afcbb6f044e461d3e4e6a03455a"
  license "Apache-2.0"
  head "https://github.com/frdminc/sudo-secretspec.git", branch: "sudo-main"

  depends_on "pkg-config" => :build
  depends_on "rust" => :build
  # install.rs targets /private/etc and the sudoers boundary it manages is
  # macOS-only, so there is nothing for this formula to do on Linux.
  depends_on :macos
  # The companion builds rusqlite against the system SQLite rather than the
  # bundled copy, which hangs in libsqlite3-sys on macOS. pkg-config finds it at
  # build time, and it resolves to Homebrew's sqlite rather than the one in
  # /usr/lib -- `otool -L` on the installed companion shows a link against
  # /opt/homebrew/opt/sqlite/lib/libsqlite3.dylib. So this is a runtime
  # dependency, not just a build one: declaring it `=> :build` would let
  # Homebrew remove sqlite and leave an installed binary that cannot start.
  depends_on "sqlite"

  def install
    system "cargo", "install", "--locked", "--root", prefix, "--path", "secretspec"

    # The companion goes to libexec, which Homebrew does not link, so it never
    # lands on PATH. It is only a bootstrap: the binary you run day to day is
    # the one `sudo-secretspec install` places at /usr/local/bin, and that path
    # is what the sudoers policy and the installed manifest are pinned to. A
    # linked keg copy would shadow it with a same-version, different-hash
    # binary that `doctor` cannot currently detect.
    staging = buildpath/"companion-root"
    system "cargo", "install", "--locked", "--root", staging, "--path", "sudo-secretspec-cli"
    libexec.install staging/"bin/sudo-secretspec"

    (share/"sudo-secretspec").install "sudo-secretspec/AI-GUIDANCE.md"
    (share/"sudo-secretspec").install "sudo-secretspec/sudo-secretspec-retired.toml"
    (share/"sudo-secretspec/skills/sudo-secretspec").install "skills/sudo-secretspec/SKILL.md"
  end

  def caveats
    <<~EOS
      Homebrew installed files only. It did not run sudo, edit sudoers, create
      users, or mutate /var/db. To opt in after reviewing the installed assets,
      explicitly run the bootstrap companion out of libexec:

        #{opt_libexec}/sudo-secretspec install --declarations /path/to/secretspec.toml

      That installs the client you use from then on at
      /usr/local/bin/sudo-secretspec. The libexec copy is deliberately not on
      PATH so it cannot shadow the installed client.

      Upgrading an installed boundary adopts the vault its own config records,
      so the command above is also the upgrade command. A store found only by
      path scan -- including the retired wrapper's, which migration leaves on
      disk on purpose -- is never adopted without --adopt-existing. See
      sudo-secretspec/AI-GUIDANCE.md in the source distribution.
    EOS
  end

  test do
    assert_match "0.19.1-sudo.29", shell_output("#{bin}/secretspec --version")
    assert_match "sudo-secretspec 0.19.1-sudo.29", shell_output("#{libexec}/sudo-secretspec --version")
    # The companion must never be linked onto PATH; see the install comment.
    refute_path_exists bin/"sudo-secretspec"
  end
end

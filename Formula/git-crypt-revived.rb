class GitCryptRevived < Formula
  desc "Transparent file encryption in Git (revived fork with age, Shamir, and YubiKey support)"
  homepage "https://github.com/ramene/git-crypt"
  url "https://github.com/ramene/git-crypt/archive/refs/tags/v0.9.0.tar.gz"
  sha256 ""
  license "GPL-3.0-or-later"

  depends_on "openssl"

  def install
    system "make", "ENABLE_MAN=no",
                   "CXXFLAGS=-I#{Formula["openssl"].opt_include} #{ENV.cflags}",
                   "LDFLAGS=-L#{Formula["openssl"].opt_lib} -lcrypto"
    system "make", "install", "PREFIX=#{prefix}"
  end

  test do
    assert_match "git-crypt 0.9.0", shell_output("#{bin}/git-crypt version")
  end
end

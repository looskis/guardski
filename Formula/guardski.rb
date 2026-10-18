class Guardski < Formula
  include Language::Python::Virtualenv

  desc "On-premises scheduled security scanning and audit evidence"
  homepage "https://github.com/looskis/guardski"
  url "https://github.com/looskis/guardski/releases/download/v0.1.0/guardski-0.1.0.tar.gz"
  sha256 "0b49e8dfe200c5593b70c77422ffed0b3ee79aeba06cfb9eaa840f87adb82c7a"
  license "AGPL-3.0-or-later"
  head "https://github.com/looskis/guardski.git", branch: "main"

  depends_on "cryptography" => :no_linkage
  depends_on "python@3.15"

  # Build backend. Homebrew disables build isolation, so hatchling and its
  # dependencies have to be present in the virtualenv before the sdist builds.
  resource "hatchling" do
    url "https://files.pythonhosted.org/packages/32/64/4afe5dd77b2939a93e8c9513f8082dbd049ecba9c1484a379a0f6ae29d6b/hatchling-1.33.0-py3-none-any.whl"
    sha256 "415290b84f464d2884303fca8974d38e7b85579069fab02a15db0828fbb1446d"
  end

  resource "packaging" do
    url "https://files.pythonhosted.org/packages/7d/fa/3944b40b07da9ce895c0e6303a5ab7d53da063554f534556b134a54d6093/packaging-26.3.tar.gz"
    sha256 "94edc256424af38762eb31306eed28beb9f0efc50a8837492c9d6fd6004aed79"
  end

  resource "pathspec" do
    url "https://files.pythonhosted.org/packages/5a/82/42f767fc1c1143d6fd36efb827202a2d997a375e160a71eb2888a925aac1/pathspec-1.1.1.tar.gz"
    sha256 "17db5ecd524104a120e173814c90367a96a98d07c45b2e10c2f3919fff91bf5a"
  end

  resource "pluggy" do
    url "https://files.pythonhosted.org/packages/bf/db/7fc19e6f2dc92a966727031389fc2e08b558f0f25eb7403c1119ad4713cd/pluggy-1.7.0.tar.gz"
    sha256 "d1eaa46ebb595891b860ab086b4d09c8588af65ebd4361b8e8f4bb8920b90ba8"
  end

  resource "tomlkit" do
    url "https://files.pythonhosted.org/packages/da/46/7d84138a60a8bd796825b2d38ebe92d0d16501ca57d501b7c5d677401bbc/tomlkit-0.15.2-py3-none-any.whl"
    sha256 "05562412163a3037b94497385fb7f9204c637bc605af7a48199e41cf2272f437"
  end

  resource "trove-classifiers" do
    url "https://files.pythonhosted.org/packages/bf/93/af436dfaa845cab5d96f0adbc1e4f3730532d37fa249e4eb796fb1d7fc82/trove_classifiers-2026.9.21.13.tar.gz"
    sha256 "0a9ebc8d4e2f3e8a22848c5258033035bec17a3012ac3fea16dbaa764489eb71"
  end

  # Runtime dependencies.
  resource "croniter" do
    url "https://files.pythonhosted.org/packages/cd/ba/d678e5bd329646ca51d3c92addbc77804e86d21f4b6b6a027218e6abb010/croniter-6.2.4-py3-none-any.whl"
    sha256 "8ef3d544107a5c05a150a2d78f8bf5a8eb9c5c4d93405a736b824109574e3f4d"
  end

  resource "defusedxml" do
    url "https://files.pythonhosted.org/packages/07/6c/aa3f2f849e01cb6a001cd8554a88d4c77c5c1a31c95bdf1cf9301e6d9ef4/defusedxml-0.7.1-py2.py3-none-any.whl"
    sha256 "a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61"
  end

  resource "python-dateutil" do
    url "https://files.pythonhosted.org/packages/5a/17/cebee01d1c0c1441174cf0456ddc91b280d79acb65340c05e41d77866ee8/python_dateutil-3.0.0-py2.py3-none-any.whl"
    sha256 "3c79630202e4152c6add678446984236efe4f57e84d8e892aab0637bab82e9fd"
  end

  resource "six" do
    url "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl"
    sha256 "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"
  end

  resource "tzdata" do
    url "https://files.pythonhosted.org/packages/94/21/1e5995a1c920cce14e4bffae20c665ec10e7ed03ab25e006cd741092b718/tzdata-2026.5-py2.py3-none-any.whl"
    sha256 "b683bd1b6659ddcd810ff02ad09ba821d4bf1065072805063eb35c49617905ac"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/guardski --version")
    assert_match "On-premises security scanning", shell_output("#{bin}/guardski --help")
  end
end

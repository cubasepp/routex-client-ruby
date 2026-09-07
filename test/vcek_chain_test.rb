# frozen_string_literal: true

require_relative "test_helper"

class VcekChainTest < Minitest::Test
  def anchors = Routex::AmdRootStore.certificates
  def by_cn = anchors.to_h { |c| [c.subject_common_name, c] }

  def test_bundles_all_three_amd_generations
    assert_equal %w[ARK-Genoa ARK-Milan ARK-Turin SEV-Genoa SEV-Milan SEV-Turin], by_cn.keys.sort
  end

  # AMD signs its chain with RSASSA-PSS/SHA-384. This is the check that proves
  # Ruby's OpenSSL handles that scheme; without it the whole chain is unusable.
  def test_amd_roots_verify_their_own_rsassa_pss_signatures
    %w[Genoa Milan Turin].each do |generation|
      ark = by_cn.fetch("ARK-#{generation}")
      ark.verify_signature_by(ark)
    end
  end

  def test_amd_intermediates_verify_against_their_root
    %w[Genoa Milan Turin].each do |generation|
      by_cn.fetch("SEV-#{generation}").verify_signature_by(by_cn.fetch("ARK-#{generation}"))
    end
  end

  def test_rejects_a_cross_generation_signature
    assert_raises(Routex::VcekChainError) do
      by_cn.fetch("SEV-Milan").verify_signature_by(by_cn.fetch("ARK-Genoa"))
    end
  end

  def test_roots_are_certificate_authorities_that_may_sign
    anchors.each do |cert|
      assert cert.certificate_authority?, "#{cert.subject_common_name} is not a CA"
      assert cert.allows_certificate_signing?, "#{cert.subject_common_name} may not sign"
    end
  end

  def test_absent_amd_extensions_read_as_nil
    ark = by_cn.fetch("ARK-Milan")
    assert_nil ark.extension_as_ia5_string(Routex::VcekCertificate::OIDS[:product_name])
    assert_nil ark.extension_as_integer(Routex::VcekCertificate::OIDS[:bl_spl])
  end

  def test_requires_the_amd_product_name_extension_on_a_leaf
    assert_raises(Routex::VcekChainError) { by_cn.fetch("ARK-Milan").product_name }
  end

  def test_rejects_an_empty_chain
    assert_raises(Routex::VcekChainError) { Routex::VcekChain.verify("") }
  end

  def test_rejects_a_chain_with_no_trusted_issuer
    pem = File.read(Routex::AmdRootStore::PEM_PATH)
    leaf_only = pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).first
    assert_raises(Routex::VcekChainError) { Routex::VcekChain.verify(leaf_only, roots: []) }
  end

  def test_infers_the_cpu_family_from_the_product_name
    assert_equal :milan, Routex::VcekChain.infer_family("Milan-B0")
    assert_equal :genoa, Routex::VcekChain.infer_family("Genoa-A0")
    assert_equal :genoa, Routex::VcekChain.infer_family("Bergamo-A1")
    assert_equal :turin, Routex::VcekChain.infer_family("Turin-B0")
    assert_raises(Routex::VcekChainError) { Routex::VcekChain.infer_family("Rome-B0") }
  end
end

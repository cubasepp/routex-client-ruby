# frozen_string_literal: true

require_relative "amd_root_store"
require_relative "vcek_certificate"

module Routex
  # Builds and validates the VCEK -> ASK -> ARK path. Port of VcekChain.kt.
  module VcekChain
    Result = Struct.new(:family, :product_name, :leaf, :vcek_tcb, keyword_init: true)

    FAMILIES = { "Milan" => :milan, "Genoa" => :genoa, "Siena" => :genoa,
                 "Bergamo" => :genoa, "Turin" => :turin }.freeze

    module_function

    def verify(chain_pem, roots: AmdRootStore.certificates, now: Time.now)
      parsed = VcekCertificate.parse_chain(chain_pem)
      raise VcekChainError, "empty VCEK chain" if parsed.empty?

      leaf = parsed.first
      path = build_path(leaf, parsed.drop(1), roots)
      verify_path_signatures(path)
      verify_constraints(path, now)

      unless leaf.subject_common_name == "SEV-VCEK"
        raise VcekChainError, "leaf subject common name is not SEV-VCEK"
      end

      product_name = leaf.product_name
      tcb = leaf.tcb
      Result.new(
        family: infer_family(product_name),
        product_name: product_name,
        leaf: leaf,
        vcek_tcb: AttestationReport::Tcb.new(
          bootloader: tcb.bootloader, tee: tcb.tee, snp: tcb.snp,
          microcode: tcb.microcode, fmc: tcb.fmc || 0, raw: 0
        )
      )
    end

    def build_path(leaf, intermediates, roots)
      path = [leaf]
      current = leaf
      loop do
        issuer_der = current.issuer_der
        anchor = roots.find { |c| c.subject_der == issuer_der }
        return path + [anchor] if anchor

        issuer = intermediates.find { |c| c.subject_der == issuer_der && !path.include?(c) }
        unless issuer
          raise VcekChainError, "no trusted issuer for subject CN=#{current.subject_common_name}"
        end

        path << issuer
        current = issuer
      end
    end

    def verify_path_signatures(path)
      path.each_cons(2) { |subject, issuer| subject.verify_signature_by(issuer) }
    end

    def verify_constraints(path, now)
      return if path.size < 2

      anchor_index = path.size - 1
      raise VcekChainError, "leaf certificate is a CA" if path[0].certificate_authority?

      path[0...anchor_index].each_with_index do |cert, i|
        raise VcekChainError, "certificate chain[#{i}] is not yet valid" if now < cert.valid_from
        raise VcekChainError, "certificate chain[#{i}] has expired" if now > cert.valid_until
      end

      (1...anchor_index).each do |i|
        issuer = path[i]
        raise VcekChainError, "intermediate chain[#{i}] is not a CA" unless issuer.certificate_authority?
        unless issuer.allows_certificate_signing?
          raise VcekChainError, "intermediate chain[#{i}] may not sign certificates"
        end
      end

      (1..anchor_index).each do |i|
        max_below = path[i].max_intermediate_certificates
        next if max_below.nil?
        raise VcekChainError, "path length constraint exceeded at chain[#{i}]" if (i - 1) > max_below
      end
    end

    def infer_family(product_name)
      base = product_name.split("-").first.to_s.strip
      FAMILIES.fetch(base) { raise VcekChainError, "unexpected VCEK product name: #{product_name}" }
    end
  end
end

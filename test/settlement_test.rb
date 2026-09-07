# frozen_string_literal: true

require_relative "test_helper"

# Exercises the settlement state machine against a stub transport. The
# attestation itself cannot be faked offline -- a valid VCEK chain requires an
# AMD-signed leaf -- so these cover the failure paths that guard it plus the
# request shape. The happy path needs the online suite; see PORTING.md.
class SettlementTest < Minitest::Test
  class StubTransport
    attr_reader :requests

    def initialize(&responder)
      @responder = responder
      @requests = []
    end

    def execute(method:, url:, headers: {}, body: nil)
      @requests << { method: method, url: url, headers: headers, body: body }
      @responder.call(@requests.last)
    end
  end

  def ok(body)
    Routex::HttpResponse.new(status: 200, headers: {}, body: body)
  end

  def settlement(transport)
    Routex::Settlement.new(base_url: "https://integration.yaxi.tech", transport: transport)
  end

  def test_posts_the_client_public_key_as_base64_json
    transport = StubTransport.new { ok("{}") }
    subject = settlement(transport)
    subject.settle rescue Routex::MalformedSettlementResponse

    request = transport.requests.first
    assert_equal :post, request[:method]
    assert_equal "https://integration.yaxi.tech/key-settlement", request[:url]
    assert_equal "application/vnd.yaxi.v5", request[:headers]["accept"]
    assert_equal Base64.strict_encode64(subject.client_public_key), JSON.parse(request[:body])["publicKey"]
  end

  def test_forwards_extra_headers
    transport = StubTransport.new { ok("{}") }
    subject = settlement(transport)
    subject.settle("yaxi-ticket-id" => "t-1") rescue Routex::MalformedSettlementResponse

    assert_equal "t-1", transport.requests.first[:headers]["yaxi-ticket-id"]
  end

  def test_raises_a_typed_error_on_a_4xx
    body = JSON.generate(Unauthorized: { userMessage: "bad key" })
    transport = StubTransport.new { Routex::HttpResponse.new(status: 401, headers: {}, body: body) }
    error = assert_raises(Routex::UnauthorizedError) { settlement(transport).settle }
    assert_equal 401, error.status
    assert_equal "bad key", error.user_message
  end

  def test_rejects_a_non_json_body
    transport = StubTransport.new { ok("not json") }
    assert_raises(Routex::MalformedSettlementResponse) { settlement(transport).settle }
  end

  def test_rejects_a_body_missing_the_attestation_report
    transport = StubTransport.new { ok(JSON.generate(vcek: "", chachaBox: "", systemVersion: {})) }
    assert_raises(Routex::MalformedSettlementResponse) { settlement(transport).settle }
  end

  def test_rejects_a_non_base64_attestation_report
    body = JSON.generate(attestationReport: "!!!not base64!!!", vcek: "", chachaBox: "", systemVersion: {})
    transport = StubTransport.new { ok(body) }
    assert_raises(Routex::MalformedSettlementResponse) { settlement(transport).settle }
  end

  # A real report with no VCEK chain must fail in the chain validator, never fall
  # through to the ChaChaBox decrypt.
  def test_rejects_a_valid_report_without_a_vcek_chain
    body = JSON.generate(
      attestationReport: Base64.strict_encode64(milan_v2_report_bytes),
      vcek: "", chachaBox: Base64.strict_encode64("x"), systemVersion: {}
    )
    transport = StubTransport.new { ok(body) }
    assert_raises(Routex::VcekChainError) { settlement(transport).settle }
  end

  def test_sealing_before_settling_is_refused
    assert_raises(Routex::NotSettledError) { settlement(StubTransport.new { ok("{}") }).seal("payload") }
  end

  def test_unsealing_works_before_settling
    subject = settlement(StubTransport.new { ok("{}") })
    sealed = Routex::ChaChaBox.seal(subject.client_public_key, "hello")
    assert_equal "hello", subject.unseal(sealed)
  end
end

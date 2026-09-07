# frozen_string_literal: true

require_relative "test_helper"

# Pins the request shapes against routex-client-lua's client.lua and core.lua.
class ClientTest < Minitest::Test
  # Stands in for ClientCore, recording what the client asked it to send.
  class RecordingCore
    attr_reader :calls
    attr_accessor :redirect_uri, :next_body

    def initialize(next_body = nil)
      @calls = []
      @next_body = next_body || JSON.generate(Result: ["a.b.c"])
    end

    def request(ticket:, path:, body: nil)
      @calls << { ticket: ticket, path: path, body: body && JSON.parse(body) }
      @next_body
    end

    def seal_payload(_ticket_id, plaintext) = "sealed:#{plaintext}"
    def trace_id = nil
    def system_version_for(_id) = nil
  end

  def setup
    @core = RecordingCore.new
    @client = Routex::Client.new(core: @core)
    @ticket = Routex::Ticket.new(service: "Accounts", id: "t-1", raw: "a.b.c")
    @credentials = { connection_id: "connection-1", user_id: "user" }
  end

  def last = @core.calls.last
  def body = last[:body]

  def test_accounts_posts_to_the_service_path
    @client.accounts(@ticket, credentials: @credentials, fields: %w[iban currency])

    assert_equal "accounts/service", last[:path]
    assert_equal %w[iban currency], body["fields"]
  end

  # connectionData, session and recurringConsents are sent as explicit nulls /
  # false rather than omitted, matching the Lua client's NULL_MARKER handling.
  def test_the_shared_envelope_sends_explicit_nulls
    @client.accounts(@ticket, credentials: @credentials)

    assert body.key?("session")
    assert_nil body["session"]
    assert body["credentials"].key?("connectionData")
    assert_nil body["credentials"]["connectionData"]
    assert_equal false, body["recurringConsents"]
    assert_equal "connection-1", body["credentials"]["connectionId"]
    assert_equal "user", body["credentials"]["userId"]
  end

  def test_omits_credentials_that_were_not_given
    @client.accounts(@ticket, credentials: { connection_id: "connection-1" })

    refute body["credentials"].key?("userId")
    refute body["credentials"].key?("password")
  end

  def test_base64_encodes_binary_credentials_and_session
    @client.accounts(@ticket,
                     credentials: { connection_id: "c", connection_data: "raw-consent" },
                     session: "raw-session", recurring_consents: true)

    assert_equal "raw-consent", Base64.strict_decode64(body["credentials"]["connectionData"])
    assert_equal "raw-session", Base64.strict_decode64(body["session"])
    assert_equal true, body["recurringConsents"]
  end

  def test_balances_carries_the_account_list
    @client.balances(@ticket, credentials: @credentials, accounts: [{ "iban" => "DE02" }])

    assert_equal "balances/service", last[:path]
    assert_equal [{ "iban" => "DE02" }], body["accounts"]
  end

  def test_transactions_sends_only_the_envelope
    @client.transactions(@ticket, credentials: @credentials)

    assert_equal "transactions/service", last[:path]
    assert_equal %w[credentials session recurringConsents].sort, body.keys.sort
  end

  def test_collect_payment_path
    @client.collect_payment(@ticket, credentials: @credentials, account: { "iban" => "DE02" })

    assert_equal "collect-payment/service", last[:path]
    assert_equal({ "iban" => "DE02" }, body["account"])
  end

  def test_transfer_formats_the_requested_execution_date
    @client.transfer(@ticket, credentials: @credentials,
                     details: { "amount" => { "amount" => "10.00", "currency" => "EUR" } },
                     product: "SepaCreditTransfer",
                     requested_execution_date: Date.new(2026, 3, 4))

    assert_equal "transfer/service", last[:path]
    assert_equal "2026-03-04", body["requestedExecutionDate"]
    assert_equal "SepaCreditTransfer", body["product"]
  end

  def test_transfer_passes_a_string_date_through
    @client.transfer(@ticket, credentials: @credentials, details: {},
                     requested_execution_date: "2026-03-04")

    assert_equal "2026-03-04", body["requestedExecutionDate"]
  end

  def test_transfer_omits_an_absent_date
    @client.transfer(@ticket, credentials: @credentials, details: {})

    refute body.key?("requestedExecutionDate")
  end

  # The interrupt endpoints are /response and /confirmation, and the context
  # goes back Base64-encoded.
  def test_respond_posts_the_context_and_answer
    @client.respond_accounts(@ticket, "raw-context", "123456")

    assert_equal "accounts/response", last[:path]
    assert_equal "raw-context", Base64.strict_decode64(body["context"])
    assert_equal "123456", body["response"]
  end

  def test_confirm_posts_only_the_context
    @client.confirm_collect_payment(@ticket, "raw-context")

    assert_equal "collect-payment/confirmation", last[:path]
    assert_equal "raw-context", Base64.strict_decode64(body["context"])
    assert_equal %w[context], body.keys
  end

  def test_every_service_has_respond_and_confirm
    Routex::Client::SERVICE_PATHS.each_key do |service|
      assert_respond_to @client, :"respond_#{service}"
      assert_respond_to @client, :"confirm_#{service}"
    end
  end

  def test_search_sends_filters_and_defaults_iban_detection
    @core.next_body = JSON.generate([{ "name" => "Sparkasse" }])
    result = @client.search(@ticket, filters: [{ "Term" => "sparkasse" }], limit: 20)

    assert_equal "search", last[:path]
    assert_equal false, body["ibanDetection"]
    assert_equal 20, body["limit"]
    assert_equal [{ "name" => "Sparkasse" }], result
  end

  def test_search_works_without_a_ticket
    @core.next_body = JSON.generate([])
    @client.search(filters: [])

    assert_nil last[:ticket]
  end

  def test_info_is_a_get_on_the_connection_id
    @core.next_body = JSON.generate("name" => "Sparkasse")
    result = @client.info(@ticket, "connection-1")

    assert_equal "info/connection-1", last[:path]
    assert_nil last[:body]
    assert_equal "Sparkasse", result["name"]
  end

  def test_register_redirect_uri_returns_the_redirect_url
    @core.next_body = JSON.generate(redirectUrl: "https://bank.example/go")
    url = @client.register_redirect_uri(@ticket, "h-1", "myapp://cb")

    assert_equal "redirects", last[:path]
    assert_equal "h-1", body["handle"]
    assert_equal "myapp://cb", body["redirectUri"]
    assert_equal "https://bank.example/go", url
  end

  def test_register_redirect_uri_raises_when_the_url_is_missing
    @core.next_body = JSON.generate(other: "value")
    assert_raises(Routex::ResponseError) { @client.register_redirect_uri(@ticket, "h", "u") }
  end

  # The trace id is sealed, then url-safe Base64, then part of the path.
  def test_trace_seals_the_id_into_the_path
    @core.next_body = JSON.generate("events" => [])
    @client.trace(@ticket, "trace-1")

    assert last[:path].start_with?("traces/")
    encoded = last[:path].delete_prefix("traces/")
    assert_equal "sealed:trace-1", Base64.urlsafe_decode64(encoded)
  end

  def test_a_service_call_returns_a_parsed_response
    @core.next_body = JSON.generate(Redirect: { url: "https://bank.example",
                                                context: Base64.strict_encode64("tok") })
    response = @client.accounts(@ticket, credentials: @credentials)

    assert_kind_of Routex::Redirect, response
    assert_equal "tok", response.context
  end
end

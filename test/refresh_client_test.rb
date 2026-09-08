# frozen_string_literal: true

require_relative "test_helper"

# Pins the non-interactive request and response shapes against
# routex-client-lua's refresh.lua, cross-checked with the Kotlin
# RoutexRefreshClient.
class RefreshClientTest < Minitest::Test
  def setup
    @core = ClientTest::RecordingCore.new(JSON.generate(result: { "accounts" => [] }))
    @client = Routex::RefreshClient.new(core: @core)
    @ticket = Routex::Ticket.new(service: "Accounts", id: "t-1", raw: "a.b.c")
    @connection_data = "raw-connection-data"
  end

  def last = @core.calls.last
  def body = last[:body]

  def test_accounts_posts_to_the_non_interactive_path
    @client.accounts(@ticket, connection_data: @connection_data, fields: %w[iban])

    assert_equal "accounts/non-interactive", last[:path]
    assert_equal %w[iban], body["fields"]
  end

  def test_balances_posts_to_the_non_interactive_path
    @core.next_body = JSON.generate(result: { "balances" => [] })
    @client.balances(@ticket, connection_data: @connection_data, accounts: [{ "iban" => "DE02" }])

    assert_equal "balances/non-interactive", last[:path]
    assert_equal [{ "iban" => "DE02" }], body["accounts"]
  end

  def test_transactions_takes_its_scope_from_the_ticket
    @core.next_body = JSON.generate(result: [])
    @client.transactions(@ticket, connection_data: @connection_data)

    assert_equal "transactions/non-interactive", last[:path]
    assert_equal %w[connectionData], body.keys
  end

  def test_connection_data_is_base64_encoded
    @client.accounts(@ticket, connection_data: @connection_data)

    assert_equal @connection_data, Base64.strict_decode64(body["connectionData"])
  end

  # Unlike the interactive envelope, absent values are omitted rather than sent
  # as explicit nulls.
  def test_omits_absent_values_rather_than_sending_nulls
    @client.accounts(@ticket, connection_data: @connection_data)

    refute body.key?("session")
    refute body.key?("userInSession")
    refute body.key?("filter")
  end

  def test_sends_the_session_when_given
    @client.accounts(@ticket, connection_data: @connection_data, session: "raw-session")

    assert_equal "raw-session", Base64.strict_decode64(body["session"])
  end

  def test_requires_connection_data
    assert_raises(ArgumentError) { @client.accounts(@ticket, connection_data: nil) }
    assert_raises(ArgumentError) { @client.accounts(@ticket, connection_data: "") }
  end

  def test_user_in_session_on_this_connection
    @client.user_in_session = Routex::RefreshClient::UserInSession::ON_THIS_CONNECTION
    @client.accounts(@ticket, connection_data: @connection_data)

    assert_equal "connection", body["userInSession"]
  end

  def test_user_in_session_at_an_ip_address
    @client.user_in_session = Routex::RefreshClient::UserInSession.at("203.0.113.7")
    @client.accounts(@ticket, connection_data: @connection_data)

    assert_equal "203.0.113.7", body["userInSession"]
  end

  def test_user_in_session_can_be_set_at_construction
    client = Routex::RefreshClient.new(core: @core, user_in_session: "198.51.100.4")
    client.accounts(@ticket, connection_data: @connection_data)

    assert_equal "198.51.100.4", body["userInSession"]
  end

  # The payload comes back directly -- no JWT envelope, no interrupts.
  def test_returns_the_payload_directly
    @core.next_body = JSON.generate(result: { "accounts" => [{ "iban" => "DE02" }] })
    response = @client.accounts(@ticket, connection_data: @connection_data)

    assert_kind_of Routex::RefreshClient::Response, response
    assert_equal [{ "iban" => "DE02" }], response.result["accounts"]
    assert_nil response.session
    assert_nil response.connection_data
  end

  # Connection data can be rotated by the service; callers must persist it.
  def test_decodes_a_rotated_session_and_connection_data
    @core.next_body = JSON.generate(result: {},
                                    session: Base64.strict_encode64("new-session"),
                                    connectionData: Base64.strict_encode64("new-connection"))
    response = @client.accounts(@ticket, connection_data: @connection_data)

    assert_equal "new-session", response.session
    assert_equal "new-connection", response.connection_data
  end

  def test_rejects_a_non_base64_connection_data_in_the_response
    @core.next_body = JSON.generate(result: {}, connectionData: "!!!not base64!!!")

    assert_raises(Routex::ResponseError) { @client.accounts(@ticket, connection_data: @connection_data) }
  end

  def test_rejects_a_malformed_response
    @core.next_body = "{"

    assert_raises(Routex::ResponseError) { @client.accounts(@ticket, connection_data: @connection_data) }
  end

  def test_exposes_the_discovery_endpoints
    @core.next_body = JSON.generate([])
    @client.search(@ticket, filters: [])
    assert_equal "search", last[:path]

    @core.next_body = JSON.generate("name" => "Sparkasse")
    @client.info(@ticket, "connection-1")
    assert_equal "info/connection-1", last[:path]
  end

  # Payments and transfers are inherently interactive and must not appear here.
  def test_does_not_expose_the_interactive_services
    %i[transfer collect_payment respond_accounts confirm_accounts register_redirect_uri].each do |method|
      refute_respond_to @client, method
    end
  end
end

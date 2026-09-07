# frozen_string_literal: true

require_relative "test_helper"

class TicketIssuerTest < Minitest::Test
  SECRET = "s3cret-hmac-key-bytes"
  FIXED_NOW = Time.at(1_700_000_000)

  def issuer(**overrides)
    Routex::TicketIssuer.new(
      api_key_id: "api-key-2eeba71f", api_key_secret: SECRET, clock: -> { FIXED_NOW }, **overrides
    )
  end

  def decode(segment)
    JSON.parse(Base64.urlsafe_decode64(segment.ljust((segment.size + 3) / 4 * 4, "=")))
  end

  def test_issues_a_compact_jwt_with_three_segments
    assert_equal 3, issuer.accounts.raw.split(".").size
  end

  def test_header_pins_hs256_and_the_key_id
    header = decode(issuer.accounts.raw.split(".").first)
    assert_equal({ "alg" => "HS256", "typ" => "JWT", "kid" => "api-key-2eeba71f" }, header)
  end

  def test_claims_carry_the_service_and_ticket_id
    ticket = issuer.balances
    claims = decode(ticket.raw.split(".")[1])
    assert_equal "Balances", claims.dig("data", "service")
    assert_equal ticket.id, claims.dig("data", "id")
  end

  def test_expiry_honours_the_ttl
    claims = decode(issuer(ttl: 300).accounts.raw.split(".")[1])
    assert_equal FIXED_NOW.to_i + 300, claims["exp"]
  end

  def test_per_call_ttl_overrides_the_default
    claims = decode(issuer.accounts(ttl: 60).raw.split(".")[1])
    assert_equal FIXED_NOW.to_i + 60, claims["exp"]
  end

  def test_signature_verifies_against_the_api_key_secret
    header, payload, signature = issuer.accounts.raw.split(".")
    expected = Base64.urlsafe_encode64(
      OpenSSL::HMAC.digest("SHA256", SECRET, "#{header}.#{payload}"), padding: false
    )
    assert_equal expected, signature
  end

  def test_base64_secret_and_raw_secret_agree
    from_base64 = Routex::TicketIssuer.new(
      api_key_id: "k", base64_secret: Base64.strict_encode64(SECRET), clock: -> { FIXED_NOW }
    )
    from_raw = Routex::TicketIssuer.new(
      api_key_id: "k", api_key_secret: SECRET, clock: -> { FIXED_NOW }
    )
    fixed = "11111111-1111-1111-1111-111111111111"
    assert_equal from_raw.accounts(ticket_id: fixed).raw, from_base64.accounts(ticket_id: fixed).raw
  end

  def test_carries_service_specific_ticket_data
    data = { "amount" => { "amount" => "10.00", "currency" => "EUR" } }
    claims = decode(issuer.collect_payment(data: data).raw.split(".")[1])
    assert_equal "CollectPayment", claims.dig("data", "service")
    assert_equal data, claims.dig("data", "data")
  end

  def test_ticket_round_trips_through_parse
    ticket = issuer.transactions
    parsed = Routex::Ticket.parse(ticket.raw)
    assert_equal ticket.id, parsed.id
    assert_equal "Transactions", parsed.service
  end

  def test_rejects_a_blank_key_id
    assert_raises(ArgumentError) { Routex::TicketIssuer.new(api_key_id: " ", api_key_secret: SECRET) }
  end

  def test_rejects_an_empty_secret
    assert_raises(ArgumentError) { Routex::TicketIssuer.new(api_key_id: "k", api_key_secret: "") }
  end

  def test_rejects_a_non_positive_ttl
    assert_raises(ArgumentError) { Routex::TicketIssuer.new(api_key_id: "k", api_key_secret: SECRET, ttl: 0) }
  end
end

# frozen_string_literal: true

require_relative "test_helper"

# Error envelope variants taken from routex-client-lua's core.lua _handleResponse.
class ErrorDispatcherTest < Minitest::Test
  def dispatch(status, hash) = Routex::ErrorDispatcher.dispatch(status, JSON.generate(hash))

  {
    "UnexpectedError" => Routex::UnexpectedError,
    "Canceled" => Routex::CanceledError,
    "InvalidCredentials" => Routex::InvalidCredentialsError,
    "ServiceBlocked" => Routex::ServiceBlockedError,
    "Unauthorized" => Routex::UnauthorizedError,
    "AccessExceeded" => Routex::AccessExceededError,
    "PeriodOutOfBounds" => Routex::PeriodOutOfBoundsError,
    "UnsupportedProduct" => Routex::UnsupportedProductError,
    "PaymentFailed" => Routex::PaymentFailedError,
    "UnexpectedValue" => Routex::UnexpectedValueError,
    "TicketError" => Routex::TicketError,
    "ProviderError" => Routex::ProviderError,
    "InterruptError" => Routex::InterruptError
  }.each do |variant, klass|
    define_method(:"test_maps_#{variant}_to_#{klass.name.split("::").last}") do
      assert_kind_of klass, dispatch(400, variant => {})
    end
  end

  def test_every_variant_is_a_service_error
    Routex::ErrorDispatcher::VARIANTS.each_key do |variant|
      assert_kind_of Routex::ServiceError, dispatch(400, variant => {})
    end
  end

  def test_carries_the_user_message
    error = dispatch(400, InvalidCredentials: { userMessage: "PIN falsch" })

    assert_equal "PIN falsch", error.user_message
    assert_equal "PIN falsch", error.message
    assert_equal 400, error.status
  end

  def test_carries_a_code_where_the_variant_has_one
    error = dispatch(403, ServiceBlocked: { code: "Temporary", userMessage: "blocked" })

    assert_equal "Temporary", error.code
  end

  def test_unsupported_product_uses_reason_as_its_code
    error = dispatch(400, UnsupportedProduct: { reason: "NotOffered", userMessage: "nope" })

    assert_equal "NotOffered", error.code
  end

  def test_ticket_error_appends_a_hint_for_an_unknown_key
    error = dispatch(400, TicketError: { code: "UnknownKey", error: "no such key" })

    assert_equal "UnknownKey", error.code
    assert_match(/Base64 encoded/, error.message)
    assert_equal "no such key", error.user_message
  end

  def test_ticket_error_appends_a_hint_for_an_invalid_signature
    error = dispatch(400, TicketError: { code: "Invalid", error: "InvalidSignature" })

    assert_match(/HMAC-SHA256/, error.message)
  end

  def test_ticket_error_without_a_known_hint_is_left_alone
    error = dispatch(400, TicketError: { code: "Expired", error: "ticket expired" })

    assert_equal "ticket expired", error.message
  end

  def test_a_bare_404_becomes_not_found
    assert_kind_of Routex::NotFoundError, Routex::ErrorDispatcher.dispatch(404, "{}")
  end

  # A 404 that still carries a typed envelope keeps the specific error.
  def test_a_404_with_a_typed_envelope_keeps_its_type
    assert_kind_of Routex::UnauthorizedError, dispatch(404, Unauthorized: { userMessage: "no" })
  end

  def test_an_unrecognised_body_becomes_a_response_error
    error = Routex::ErrorDispatcher.dispatch(500, "<html>gateway</html>")

    assert_kind_of Routex::ResponseError, error
    assert_equal 500, error.status
    assert_equal "<html>gateway</html>", error.body
  end

  def test_an_unknown_variant_becomes_a_response_error
    assert_kind_of Routex::ResponseError, dispatch(400, SomethingNew: { userMessage: "?" })
  end

  def test_attestation_errors_are_not_service_errors
    refute_operator Routex::AttestationError, :<=, Routex::ServiceError
    assert_operator Routex::MeasurementMismatch, :<=, Routex::AttestationError
    assert_operator Routex::VcekChainError, :<=, Routex::AttestationError
  end
end

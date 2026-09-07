# frozen_string_literal: true

require_relative "test_helper"

# Wire shapes are taken from routex-client-lua's response.lua, which is the
# authoritative description of what the services actually send.
class ResponseTest < Minitest::Test
  def parse(hash) = Routex::Response.parse(JSON.generate(hash))

  # Result's payload is a positional array [jwt, session, connectionData], not
  # an object -- getting this wrong silently loses the session and consent.
  def test_parses_a_result_from_its_positional_array
    response = parse(Result: ["header.payload.sig", Base64.strict_encode64("sess"),
                              Base64.strict_encode64("conn")])

    assert response.result?
    refute response.interrupt?
    assert_equal "header.payload.sig", response.jwt
    assert_equal "sess", response.session
    assert_equal "conn", response.connection_data
  end

  def test_result_session_and_connection_data_are_optional
    response = parse(Result: ["a.b.c"])

    assert_equal "a.b.c", response.jwt
    assert_nil response.session
    assert_nil response.connection_data
  end

  def test_rejects_a_result_that_is_not_an_array
    assert_raises(Routex::ResponseError) { parse(Result: { jwt: "a.b.c" }) }
  end

  def test_rejects_a_result_without_a_jwt
    assert_raises(Routex::ResponseError) { parse(Result: []) }
  end

  # Dialog#context is the dialog's category; the continuation token lives on the
  # input and is Base64-encoded binary.
  def test_parses_a_confirmation_dialog
    response = parse(Dialog: { context: "Sca", message: "Confirm in your app",
                               input: { Confirmation: { context: Base64.strict_encode64("tok"),
                                                        pollingDelaySecs: 5 } } })

    assert response.dialog?
    assert response.interrupt?
    assert response.confirmation?
    assert_equal Routex::Response::DialogContext::SCA, response.context
    assert_equal "Confirm in your app", response.message
    assert_equal "tok", response.input_context
    assert_equal 5, response.input.polling_delay_secs
  end

  def test_parses_a_selection_dialog
    options = [{ "key" => "m1", "label" => "pushTAN" }, { "key" => "m2", "label" => "chipTAN" }]
    response = parse(Dialog: { context: "Sca",
                               input: { Selection: { options: options,
                                                     context: Base64.strict_encode64("tok") } } })

    assert response.selection?
    assert_equal %w[m1 m2], response.input.options.map { |o| o["key"] }
    assert_equal "tok", response.input_context
  end

  def test_parses_a_field_dialog_and_reports_masking
    response = parse(Dialog: { input: { Field: { type: "Number", secrecyLevel: "Otp",
                                                 context: Base64.strict_encode64("tok"),
                                                 minLength: 6, maxLength: 8 } } })

    assert response.field?
    assert_equal "Number", response.input.type
    assert response.input.masked?
    assert_equal 6, response.input.min_length
    assert_equal 8, response.input.max_length
  end

  def test_a_plain_field_is_not_masked
    response = parse(Dialog: { input: { Field: { type: "Text", secrecyLevel: "Plain",
                                                 context: Base64.strict_encode64("t") } } })
    refute response.input.masked?
  end

  def test_decodes_a_dialog_image
    response = parse(Dialog: { message: "Scan",
                               image: { mimeType: "image/gif", data: Base64.strict_encode64("GIF89a") },
                               input: { Confirmation: { context: Base64.strict_encode64("t") } } })

    assert_equal "image/gif", response.image.mime_type
    assert_equal "GIF89a", response.image.data
    assert_nil response.image.hhd_uc_data
  end

  def test_rejects_an_unknown_dialog_context
    assert_raises(Routex::ResponseError) do
      parse(Dialog: { context: "Nope", input: { Confirmation: { context: "dA==" } } })
    end
  end

  def test_rejects_an_unknown_field_type
    assert_raises(Routex::ResponseError) do
      parse(Dialog: { input: { Field: { type: "Rune", secrecyLevel: "Plain", context: "dA==" } } })
    end
  end

  def test_rejects_an_unknown_secrecy_level
    assert_raises(Routex::ResponseError) do
      parse(Dialog: { input: { Field: { type: "Text", secrecyLevel: "Whisper", context: "dA==" } } })
    end
  end

  def test_parses_a_redirect
    response = parse(Redirect: { url: "https://bank.example/sca",
                                 context: Base64.strict_encode64("tok") })

    assert response.redirect?
    assert_equal "https://bank.example/sca", response.url
    assert_equal "tok", response.context
  end

  def test_parses_a_redirect_handle
    response = parse(RedirectHandle: { handle: "h-1", context: Base64.strict_encode64("tok") })

    assert response.redirect_handle?
    assert_equal "h-1", response.handle
    assert_equal "tok", response.context
  end

  def test_rejects_an_unknown_variant
    assert_raises(Routex::ResponseError) { parse(Nope: {}) }
  end

  def test_rejects_malformed_json
    assert_raises(Routex::ResponseError) { Routex::Response.parse("{") }
  end

  def test_rejects_a_non_base64_context
    assert_raises(Routex::ResponseError) do
      parse(Redirect: { url: "https://x.example", context: "!!!not base64!!!" })
    end
  end
end

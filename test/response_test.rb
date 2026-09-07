# frozen_string_literal: true

require_relative "test_helper"

class ServiceResponseTest < Minitest::Test
  def test_parses_a_result
    response = Routex::ServiceResponse.parse(
      JSON.generate(Result: { authenticated: { jwt: "e.y.z" }, session: "sess-1" })
    )
    assert response.result?
    assert_equal "e.y.z", response.jwt
    assert_equal "sess-1", response.session
  end

  def test_parses_a_dialog_and_exposes_its_input
    response = Routex::ServiceResponse.parse(
      JSON.generate(Dialog: { dialog: { input: { "Field" => { "label" => "TAN" } } }, context: "ctx-1" })
    )
    assert response.dialog?
    assert_equal "ctx-1", response.context
    assert_equal({ "Field" => { "label" => "TAN" } }, response.dialog_input)
  end

  def test_parses_a_redirect
    response = Routex::ServiceResponse.parse(
      JSON.generate(Redirect: { redirect: { url: "https://bank.example" }, context: "ctx-2" })
    )
    assert response.redirect?
    assert_equal "ctx-2", response.context
  end

  def test_rejects_an_unknown_variant
    assert_raises(Routex::Error) { Routex::ServiceResponse.parse(JSON.generate(Nope: {})) }
  end

  def test_rejects_a_multi_key_object
    assert_raises(Routex::Error) { Routex::ServiceResponse.parse(JSON.generate(Result: {}, Dialog: {})) }
  end

  def test_rejects_malformed_json
    assert_raises(Routex::Error) { Routex::ServiceResponse.parse("{") }
  end
end

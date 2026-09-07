# frozen_string_literal: true

require "base64"
require "json"
require_relative "errors"

module Routex
  # Responses from the interactive Open Banking services: a Result carrying the
  # service data, or one of the interrupts that need user action before the flow
  # can continue. See https://docs.yaxi.tech/interrupts.html.
  #
  # Wire shapes are externally tagged single-key objects. Note that Result's
  # payload is a positional ARRAY, not an object, and that every `context` is
  # Base64-encoded binary that must be passed back as raw bytes.
  class Response
    attr_reader :json

    # What kind of dialog this is. Distinct from the continuation context, which
    # lives on the input.
    module DialogContext
      SCA = "Sca"
      ACCOUNTS = "Accounts"
      REDIRECT = "Redirect"
      PAYMENT_STATUS = "PaymentStatus"
      VOP_CONFIRMATION = "VopConfirmation"
      VOP_CHECK = "VopCheck"
      ALL = [SCA, ACCOUNTS, REDIRECT, PAYMENT_STATUS, VOP_CONFIRMATION, VOP_CHECK].freeze
    end

    module InputType
      ALL = %w[Date Email Number Phone Text].freeze
    end

    module SecrecyLevel
      PLAIN = "Plain"
      OTP = "Otp"
      PASSWORD = "Password"
      ALL = [PLAIN, OTP, PASSWORD].freeze
    end

    # Primary action only: confirm to proceed. pollingDelaySecs, when present,
    # is how long to wait before confirming automatically.
    Confirmation = Struct.new(:context, :polling_delay_secs, keyword_init: true)
    Selection = Struct.new(:options, :context, keyword_init: true)
    Field = Struct.new(:type, :secrecy_level, :context, :min_length, :max_length, keyword_init: true) do
      def masked? = secrecy_level != SecrecyLevel::PLAIN
    end
    Image = Struct.new(:mime_type, :data, :hhd_uc_data, keyword_init: true)

    def self.from_json(json)
      unless json.is_a?(Hash)
        raise ResponseError, "expected an externally tagged object, got #{json.class}"
      end

      case
      when json.key?("Result") then Result.new(json)
      when json.key?("Dialog") then Dialog.new(json)
      when json.key?("Redirect") then Redirect.new(json)
      when json.key?("RedirectHandle") then RedirectHandle.new(json)
      else raise ResponseError, "unexpected response variant: #{json.keys.inspect}"
      end
    end

    def self.parse(bytes)
      from_json(JSON.parse(bytes))
    rescue JSON::ParserError => e
      raise ResponseError, "malformed service response: #{e.message}"
    end

    def initialize(json)
      @json = json
    end

    def result? = is_a?(Result)
    def dialog? = is_a?(Dialog)
    def redirect? = is_a?(Redirect)
    def redirect_handle? = is_a?(RedirectHandle)
    def interrupt? = !result?
    def to_h = @json

    private

    def decode(value, field)
      return nil if value.nil?

      Base64.strict_decode64(value)
    rescue ArgumentError => e
      raise ResponseError, "could not Base64-decode #{field}: #{e.message}"
    end

    def decode!(value, field)
      decode(value, field) || raise(ResponseError, "missing #{field}")
    end
  end

  # Service data, authenticated as a signed JWT. Verify the signature in a
  # trusted environment before acting on the data; decoding without verification
  # is fine for display.
  class Result < Response
    attr_reader :jwt, :session, :connection_data

    def initialize(json)
      super
      payload = json.fetch("Result")
      unless payload.is_a?(Array)
        raise ResponseError, "Result payload must be an array, got #{payload.class}"
      end

      @jwt = payload[0] or raise ResponseError, "Result is missing its JWT"
      @session = decode(payload[1], "Result session")
      @connection_data = decode(payload[2], "Result connection data")
    end
  end

  # Meant to be shown as a dialog: a cancel affordance, the message and optional
  # image, and the interactive part in #input.
  class Dialog < Response
    attr_reader :context, :message, :image, :input

    def initialize(json)
      super
      payload = json.fetch("Dialog")

      @context = payload["context"]
      if @context && !DialogContext::ALL.include?(@context)
        raise ResponseError, "unexpected Dialog.context: #{@context}"
      end

      @message = payload["message"]
      @image = build_image(payload["image"])
      @input = build_input(payload["input"] || {})
    end

    # The continuation token to pass to respond_*/confirm_*. It lives on the
    # input, not beside it -- Dialog#context is the dialog's category.
    def input_context = @input&.context

    def confirmation? = @input.is_a?(Confirmation)
    def selection? = @input.is_a?(Selection)
    def field? = @input.is_a?(Field)

    private

    def build_image(image)
      return nil unless image

      Image.new(
        mime_type: image["mimeType"],
        data: decode!(image["data"], "Dialog.image.data"),
        hhd_uc_data: decode(image["hhdUcData"], "Dialog.image.hhdUcData")
      )
    end

    def build_input(input)
      if (confirmation = input["Confirmation"])
        Confirmation.new(
          context: decode!(confirmation["context"], "Dialog.input.Confirmation.context"),
          polling_delay_secs: confirmation["pollingDelaySecs"]
        )
      elsif (selection = input["Selection"])
        Selection.new(
          options: selection["options"] || [],
          context: decode!(selection["context"], "Dialog.input.Selection.context")
        )
      elsif (field = input["Field"])
        build_field(field)
      end
    end

    def build_field(field)
      unless InputType::ALL.include?(field["type"])
        raise ResponseError, "unexpected Dialog.input.Field.type: #{field["type"]}"
      end
      unless SecrecyLevel::ALL.include?(field["secrecyLevel"])
        raise ResponseError, "unexpected Dialog.input.Field.secrecyLevel: #{field["secrecyLevel"]}"
      end

      Field.new(
        type: field["type"],
        secrecy_level: field["secrecyLevel"],
        context: decode!(field["context"], "Dialog.input.Field.context"),
        min_length: field["minLength"],
        max_length: field["maxLength"]
      )
    end
  end

  # Send the user to #url, then confirm with #context.
  class Redirect < Response
    attr_reader :url, :context

    def initialize(json)
      super
      payload = json.fetch("Redirect")
      @url = payload["url"]
      @context = decode!(payload["context"], "Redirect.context")
    end
  end

  # An incomplete redirect: register a redirect URI with #handle to obtain the
  # URL to send the user to, then confirm with #context.
  class RedirectHandle < Response
    attr_reader :handle, :context

    def initialize(json)
      super
      payload = json.fetch("RedirectHandle")
      @handle = payload["handle"]
      @context = decode!(payload["context"], "RedirectHandle.context")
    end
  end
end

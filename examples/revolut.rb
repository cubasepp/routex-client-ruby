#!/usr/bin/env ruby
# frozen_string_literal: true

# Fetch accounts from Revolut through YAXI's integration environment.
#
#   YAXI_API_KEY_ID=api-key-... YAXI_API_KEY_SECRET=... ruby -Ilib examples/revolut.rb
#
# Optional: YAXI_USER_ID (default "user"), YAXI_REDIRECT_URI (default "myapp://callback").
#
# Proof of concept: the service layer has never run against a live endpoint, so
# request/response shapes (search filters, result keys) may need adjusting
# against the YAXI API docs. Integration URL only -- do not use in production.

require "routex"
require "json"

issuer = Routex::TicketIssuer.new(
  api_key_id: ENV.fetch("YAXI_API_KEY_ID"),
  base64_secret: ENV.fetch("YAXI_API_KEY_SECRET")
)
ticket = issuer.accounts

client = Routex::Client.new(base_url: Routex::Client::INTEGRATION_URL)

# 1. Find Revolut. Filter and result shapes are unverified.
results = client.search(ticket, filters: [{ term: "Revolut" }], limit: 5)
pp results
connection = Array(results.is_a?(Hash) ? results["results"] || results.values.first : results).first
abort "Revolut not found in search results" unless connection
connection_id = connection["id"] || connection["connectionId"]
puts "Using connection #{connection_id}"

# 2. Request accounts and drive the dialog loop.
response = client.accounts(
  ticket,
  credentials: { connection_id: connection_id, user_id: ENV.fetch("YAXI_USER_ID", "user") },
  fields: %w[iban currency ownerName]
)

until response.result?
  response =
    case response
    when Routex::Redirect
      puts "Open in your browser and approve in the Revolut app:\n#{response.url}"
      print "Press Enter when done... "
      $stdin.gets
      client.confirm_accounts(ticket, response.context)
    when Routex::RedirectHandle
      url = client.register_redirect_uri(
        ticket, response.handle, ENV.fetch("YAXI_REDIRECT_URI", "myapp://callback")
      )
      puts "Open in your browser and approve in the Revolut app:\n#{url}"
      print "Press Enter when done... "
      $stdin.gets
      client.confirm_accounts(ticket, response.context)
    when Routex::Dialog
      if response.confirmation?
        print "Confirm in your banking app, then press Enter... "
        $stdin.gets
        client.confirm_accounts(ticket, response.input_context)
      else
        print "#{response.input.inspect}\n> "
        client.respond_accounts(ticket, response.input_context, $stdin.gets.to_s.chomp)
      end
    else
      abort "Unexpected response: #{response.inspect}"
    end
end

puts "Accounts JWT:\n#{response.jwt}"
puts "\nPersist this to refresh later without the user (RefreshClient):\n" \
     "#{JSON.generate(response.connection_data)}"

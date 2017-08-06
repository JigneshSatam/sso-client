module AuthenticationsHelper
  module ClassMethods

  end

  module InstanceMethods
    def redirect_to_sso
      token = encode_jwt_token({service_url: ENV["MY_URL"] + "/authentications/login"})
      redirect_to (ENV["SSO_URL"] + "?service_token=" + token) and return
    end

    def authenticate_or_redirect_to_sso
      redirect_to_sso unless logged_in?
    end

    def encode_jwt_token(data_hash = nil)
      exp = Time.now.to_i + ENV.fetch("EXPIRE_AFTER_SECONDS") { 1.hour }.to_i
      payload = { :data => data_hash, :exp => exp }
      payload = { :data => data_hash }
      hmac_secret = Rails.configuration.sso_settings["identity_provider_secret_key"]
      return JWT.encode payload, hmac_secret, 'HS256'
    end

    def decode_jwt_token(token)
      hmac_secret = Rails.configuration.sso_settings["identity_provider_secret_key"]
      begin
        decoded_token = JWT.decode token, hmac_secret, true, { :algorithm => 'HS256' }
        payload = decoded_token.select{|decoded_part| decoded_part.key?("data") }.last
        return payload
      rescue JWT::ExpiredSignature
        # Handle expired token, e.g. logout user or deny access
        puts "Token expired thus redirecting to root_url"
        redirect_to root_url
      end
    end
  end

  def self.included(receiver)
    receiver.extend         ClassMethods
    receiver.send :include, InstanceMethods
    receiver.send :include, ServiceProvider::Login
    receiver.send :include, ServiceProvider::Logout
  end
end

class ApplicationController < ActionController::Base
  include AuthenticationsHelper
  before_action :authenticate_or_redirect_to_sso, except: [:login, :logout]
end

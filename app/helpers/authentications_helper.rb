module AuthenticationsHelper
  module ClassMethods

  end

  module InstanceMethods
    def redirect_to_sso
      token = Token.encode_jwt_token({service_url: ENV["MY_URL"] + "/authentications/login"}, ENV.fetch("EXPIRE_AFTER_SECONDS") { 1.hour })
      redirect_to (ENV["SSO_URL"] + "?service_token=" + token) and return
    end

    def authenticate_or_redirect_to_sso
      redirect_to_sso unless logged_in?
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

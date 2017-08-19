module AuthenticationsHelper
  module ClassMethods

  end

  module InstanceMethods
    def redirect_to_sso
      token = Token.encode_jwt_token({service_url: ENV["MY_URL"] + "/authentications/login"}, ENV.fetch("EXPIRE_AFTER_SECONDS") { 1.hour })
      redirect_to (ENV["SSO_URL"] + "?service_token=" + token) and return
    end

    def check_authentication
      unless logged_in?
        ErrorPrinter.print_error("Sorry, you need to login before continuing.", "Login required.")
        flash[:alert] = "Sorry, you need to login before continuing."
        return redirect_to_sso
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
  before_action :check_authentication, except: [:login]
end

module AuthenticationsHelper
  module ClassMethods

  end

  module InstanceMethods
    def log_in(jwt_token)
      if jwt_token
        # debugger
        hmac_secret = Rails.configuration.sso_settings["identity_provider_secret_key"]
        begin
          decoded_token = JWT.decode jwt_token, hmac_secret, true, { :algorithm => 'HS256' }
          payload = decoded_token.select{|decoded_part| decoded_part.key?("data") }.last
          @user_email = payload["data"]["email"] if payload
          set_session(jwt_token, payload)
          return true
        rescue JWT::ExpiredSignature
          # Handle expired token, e.g. logout user or deny access
          puts "Token expired thus redirecting to sso"
          redirect_to_sso
        end
      else
        redirect_to_sso
      end
    end

    def set_session(jwt_token, payload)
      Redis.current.set("jwt:#{jwt_token}", session.id)
      @user_email = payload["data"]["email"] if payload
      session[:user_id] = @user_email
      session[:token_id] = jwt_token
    end

    def current_user
      return @current_user if !@current_user.nil?
      if (user_id = session[:user_id])
        model = Rails.configuration.sso_settings["model"]
        begin
          logger.debug "@@@@@@@@@@ CURRENT_USER before ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
          @current_user ||= model.camelcase.constantize.where(Rails.configuration.sso_settings["identifier"].to_sym => user_id).last
          logger.debug "@@@@@@@@@@ CURRENT_USER middle ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
        rescue Exception => e
          logger.debug "@@@@@@@@@@ Thread is sleeping RESCUE #{e} @@@@@@@@@@@@@@@@"
          retry
        ensure
          logger.debug "@@@@@@@@@@ Thread in CURRENT_USER ENSURE @@@@@@@@@@@@@@@@"
          model.camelcase.constantize.connection.close
          ActiveRecord::Base.connection.close
          logger.debug "@@@@@@@@@@ CURRENT_USER ENSURE ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
        end
      end
      return @current_user
    end

    def log_out(jwt_token = nil)
      if jwt_token.present?
        log_out_from_identity_provider(jwt_token)
      else
        log_out_from_service_provider
      end
    end

    def log_out_from_service_provider
      jwt_token = session[:token_id]
      clear_session(session.id, jwt_token)
    end

    def log_out_from_identity_provider(jwt_token)
      session_id = Redis.current.get("jwt:#{jwt_token}")
      clear_session(session_id, jwt_token)
    end

    def clear_session(session_id, jwt_token)
      session[:token_id] = nil
      session[:user_id] = nil
      Redis.current.del("session:#{session_id}")
      Redis.current.del("jwt:#{jwt_token}")
    end

    def logged_in?
      !current_user.nil?
    end

    def redirect_to_sso
      redirect_to (ENV["SSO_URL"] + "?service_url=" + ENV["MY_URL"] + "/authentications/login") and return
    end

    def authenticate_or_redirect_to_sso
      redirect_to_sso unless logged_in?
    end
  end

  def self.included(receiver)
    receiver.extend         ClassMethods
    receiver.send :include, InstanceMethods
  end
end

class ApplicationController < ActionController::Base
  include AuthenticationsHelper
  before_action :authenticate_or_redirect_to_sso, except: [:login, :logout]
end

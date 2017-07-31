module AuthenticationsHelper
  module ClassMethods

  end

  module InstanceMethods
    def log_in(jwt_token)
      if jwt_token
        payload = decode_jwt_token(jwt_token)
        @user_email = payload["data"]["email"] if payload
        set_session(jwt_token, payload)
        return true
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
        model = Rails.configuration.sso_settings["model"].camelcase.constantize
        begin
          logger.debug "@@@@@@@@@@ CURRENT_USER before ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
          @current_user ||= model.where(Rails.configuration.sso_settings["model_uniq_identifier"].to_sym => user_id).last
          if (@current_user.blank? && Rails.configuration.sso_settings["create_record_on_the_fly"].downcase.to_s == true.to_s)
            model_record = model.new(Rails.configuration.sso_settings["model_uniq_identifier"].to_sym => user_id)
            if model_record.valid?
              @current_user = model_record.reload if model_record.save
            end
          end
          logger.debug "@@@@@@@@@@ CURRENT_USER middle ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
        rescue Exception => e
          logger.debug "@@@@@@@@@@ Thread is sleeping RESCUE #{e} @@@@@@@@@@@@@@@@"
          retry
        ensure
          logger.debug "@@@@@@@@@@ Thread in CURRENT_USER ENSURE @@@@@@@@@@@@@@@@"
          model.connection.close
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
      logger.debug "authentication_helper %% clear_session ====> started <===="
      store = ActionDispatch::Session::RedisStore.new(Rails.application, Rails.application.config.session_options)
      number_of_keys_removed = store.with{|redis| redis.del(session_id)}
      logger.debug "logging_out number_of_keys_removed ====> #{number_of_keys_removed} <===="
      if number_of_keys_removed == 0
        number_of_keys_removed = Redis.current.del(session_id)
        if number_of_keys_removed == 0
          keys = Redis.current.keys("*#{session_id}")
          Redis.current.del(keys)
        end
      end
      Redis.current.del("jwt:#{jwt_token}")
      session[:token_id] = nil
      session[:user_id] = nil
      logger.debug "authentication_helper %% clear_session ====> ended <===="
    end

    def logged_in?
      !current_user.nil?
    end

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
  end
end

class ApplicationController < ActionController::Base
  include AuthenticationsHelper
  before_action :authenticate_or_redirect_to_sso, except: [:login, :logout]
end

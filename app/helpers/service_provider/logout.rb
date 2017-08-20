module ServiceProvider
  module Logout
    module ClassMethods

    end

    module InstanceMethods
      def log_out(jwt_token = nil)
        if jwt_token.present?
          log_out_from_identity_provider(jwt_token)
        else
          log_out_from_service_provider
        end
      end

      def log_out_from_service_provider
        sso_session_id = session[:sso_session_id]
        uniq_identifier_value = session[:uniq_identifier]
        clear_session(session.id, sso_session_id)
        log_out_identity_provider(sso_session_id, uniq_identifier_value)
      end

      def log_out_identity_provider(sso_session_id, uniq_identifier_value)
        token = Token.encode_jwt_token({session: sso_session_id, uniq_identifier: uniq_identifier_value}, ENV.fetch("EXPIRE_AFTER_SECONDS") { 1.hour })
        make_logout_request(ENV["SSO_URL"], token)
      end

      def make_logout_request(url_string, token)
        require 'net/http'
        url = URI.parse(url_string)
        base_url_string = url.query.present? ? url.to_s.split("?" + url.query).first : url.to_s
        logout_url = URI.parse(base_url_string + "/authentications/logout")
        params = { :token => token }
        logout_url.query = URI.encode_www_form(params)
        res = Net::HTTP.get_response(logout_url)
        # req = Net::HTTP::Get.new(logout_url.to_s)
        # res = Net::HTTP.start(logout_url.host, logout_url.port) {|http|
        #   http.request(req)
        # }
        puts res.body
      end

      def log_out_from_identity_provider(jwt_token)
        payload = Token.decode_jwt_token(jwt_token)
        sso_session_id = payload["data"]["session"]
        session_id = Redis.current.get("sso_session:#{sso_session_id}")
        clear_session(session_id, sso_session_id)
      end

      def clear_session(session_id, sso_session_id)
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
        Redis.current.del("sso_session:#{sso_session_id}")
        session[:sso_session_id] = nil
        session[:uniq_identifier] = nil
        logger.debug "authentication_helper %% clear_session ====> ended <===="
      end
    end

    def self.included(receiver)
      receiver.extend         ClassMethods
      receiver.send :include, InstanceMethods
    end
  end
end

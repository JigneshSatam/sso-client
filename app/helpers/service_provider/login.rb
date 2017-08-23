module ServiceProvider
  module Login
    module ClassMethods

    end

    module InstanceMethods
      def log_in(jwt_token)
        if jwt_token
          payload = Token.decode_jwt_token(jwt_token)
          set_session(payload) if payload
          set_session_expire_at
          return true
        else
          redirect_to_sso
        end
      end

      def set_session(payload)
        sso_session_id = payload["data"]["session"]
        uniq_identifier_value = payload["data"]["uniq_identifier"]
        Redis.current.hset("sso_session-#{sso_session_id}", "session_id", session.id)
        Redis.current.hset("sso_session-#{sso_session_id}", "uniq_identifier", uniq_identifier_value)
        session[:uniq_identifier] = uniq_identifier_value
        session[:sso_session_id] = sso_session_id
      end

      def set_session_expire_at
        # if session[:last_sync].blank? || ( (sync_time = Time.now) > (session[:last_sync]) )
        if session[:last_sync].blank? || ( (sync_time = Time.now) > (session[:last_sync] + 10.minutes) )
          session[:last_sync] = sync_time
          sso_session_id = session[:sso_session_id]
          keep_alive_at_identity_provider(sso_session_id) if sso_session_id.present?
        end
        if session_timeout.present?
          session[:expire_at] = (Time.now + session_timeout)
        end
      end

      def session_expired?
        return session[:expire_at].present? && Time.now > session[:expire_at]
      end

      def current_user
        if session_expired?
          session.delete(:uniq_identifier)
          @current_user = nil
        end
        return @current_user if !@current_user.nil?
        if (uniq_identifier_value = session[:uniq_identifier])
          begin
            logger.debug "@@@@@@@@@@ CURRENT_USER before ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
            @current_user ||= model.where(uniq_identifier.to_sym => uniq_identifier_value).last
            if (@current_user.blank? && Rails.configuration.sso_settings["create_record_on_the_fly"].downcase.to_s == true.to_s)
              model_record = model.new(uniq_identifier.to_sym => uniq_identifier_value)
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
        elsif (jwt_token = params[:token]).present?
          payload = Token.decode_jwt_token(jwt_token)
          sso_session_id = payload["data"]["session"]
          uniq_identifier_value = Redis.current.hget("sso_session-#{sso_session_id}", "uniq_identifier")
          @current_user ||= model.find_by(uniq_identifier.to_sym => uniq_identifier_value)
        end
        if @current_user.present?
          set_session_expire_at
        end
        return @current_user
      end

      def logged_in?
        !current_user.nil?
      end

      def keep_alive_at_identity_provider(sso_session_id)
        token = Token.encode_jwt_token({session: sso_session_id}, ENV.fetch("EXPIRE_AFTER_SECONDS") { 1.hour })
        # make_keep_alive_request(ENV["SSO_URL"], token)
        Thread.new { make_keep_alive_request(ENV["SSO_URL"], token) }
      end

      def make_keep_alive_request(url_string, token)
        require 'net/http'
        url = URI.parse(url_string)
        base_url_string = url.query.present? ? url.to_s.split("?" + url.query).first : url.to_s
        keep_alive_url = URI.parse(base_url_string + "/authentications/keep_alive")
        params = { :token => token }
        keep_alive_url.query = URI.encode_www_form(params)
        res = Net::HTTP.get_response(keep_alive_url)
        # req = Net::HTTP::Get.new(logout_url.to_s)
        # res = Net::HTTP.start(logout_url.host, logout_url.port) {|http|
        #   http.request(req)
        # }
        puts res.body
      end
    end

    def self.included(receiver)
      receiver.extend         ClassMethods
      receiver.send :include, InstanceMethods
      receiver.send :include, Authentication
    end
  end
end

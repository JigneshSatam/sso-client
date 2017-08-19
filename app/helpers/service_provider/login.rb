module ServiceProvider
  module Login
    module ClassMethods

    end

    module InstanceMethods
      def log_in(jwt_token)
        if jwt_token
          payload = Token.decode_jwt_token(jwt_token)
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
          begin
            logger.debug "@@@@@@@@@@ CURRENT_USER before ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
            @current_user ||= model.where(uniq_identifier.to_sym => user_id).last
            if (@current_user.blank? && Rails.configuration.sso_settings["create_record_on_the_fly"].downcase.to_s == true.to_s)
              model_record = model.new(uniq_identifier.to_sym => user_id)
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
    end

    def self.included(receiver)
      receiver.extend         ClassMethods
      receiver.send :include, InstanceMethods
      receiver.send :include, Authentication
    end
  end
end

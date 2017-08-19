module Authentication
  module InstanceMethods
    def model
      begin
        @model ||= Rails.configuration.sso_settings["model"].camelcase.constantize
      rescue Exception => e
        ErrorPrinter.print_error("Insert vaid model name in sso_settings.yml file as value for the key 'model' eg: `model: 'user'` if User is the model")
        raise e
      end
    end

    def uniq_identifier
      return @uniq_identifier if @uniq_identifier
      begin
        raise "model_uniq_identifier missing in sso_settings.yml" if Rails.configuration.sso_settings["model_uniq_identifier"].blank?
      rescue Exception => e
        ErrorPrinter.print_error("Insert key value pair in sso_settings.yml file eg: `model_uniq_identifier: 'email'` if email is a column")
        raise e
      else
        return (@uniq_identifier = Rails.configuration.sso_settings["model_uniq_identifier"])
      end
    end


    def session_timeout
      return @session_timeout if @session_timeout
      if Rails.configuration.sso_settings["sso_session_timeout"].to_i > 0
        return (@session_timeout = Rails.configuration.sso_settings["sso_session_timeout"].to_i.minutes)
      else
        session[:expire_at] = nil if session[:expire_at].present?
        ErrorPrinter.print_error("Insert key value pair in sso_settings.yml file eg: `sso_session_timeout: '10'` 10 are in minutes", "You have not set session_timeout")
      end
    end

  end
  module ClassMethods
  end

  def self.included(receiver)
    receiver.extend ClassMethods
    receiver.send :include, InstanceMethods
  end
end


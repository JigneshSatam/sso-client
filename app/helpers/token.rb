module Token
  def self.encode_jwt_token(data_hash, expire_after = nil)
    payload = { :data => data_hash }
    if expire_after.present?
      exp = Time.now.to_i + expire_after.to_i.minutes.to_i
      payload.merge!({exp: exp})
      # exp = Time.now.to_i + ENV.fetch("EXPIRE_AFTER_SECONDS") { 1.hour }.to_i
      # payload = { :data => data_hash, :exp => exp }
    end
    hmac_secret = sso_secret_key
    JWT.encode payload, hmac_secret, 'HS256'
  end

  def self.decode_jwt_token(token)
    hmac_secret = sso_secret_key
    begin
      decoded_token = JWT.decode token, hmac_secret, true, { :algorithm => 'HS256' }
      payload = decoded_token.select{|decoded_part| decoded_part.key?("data") }.last
      return payload
    rescue JWT::ExpiredSignature
      # Handle expired token, e.g. logout user or deny access
      puts "Token expired thus redirecting to root_url"
      if response.location.blank?
        redirect_to root_url and return
      else
        response.location = root_url
        response.status = 301
        return
      end
    end
  end

  private
    def sso_secret_key
      return @sso_secret_key if @sso_secret_key
      begin
        raise "identity_provider_secret_key missing in sso_settings.yml" if Rails.configuration.sso_settings["identity_provider_secret_key"].blank?
      rescue Exception => e
        ErrorPrinter.print_error("Insert key value pair in sso_settings.yml file eg: identity_provider_secret_key: 'my$ecretK3y'")
        raise e
      else
        return (@sso_secret_key = Rails.configuration.sso_settings["identity_provider_secret_key"])
      end
    end
    module_function :sso_secret_key
end

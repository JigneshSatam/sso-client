module SessionsHelper

  def log_in(jwt_token)
    if jwt_token
      hmac_secret = 'my$ecretK3y'
      begin
        decoded_token = JWT.decode jwt_token, hmac_secret, true, { :algorithm => 'HS256' }
        payload = decoded_token.select{|decoded_part| decoded_part.key?("data") }.last
        @user_email = payload["data"]["email"] if payload
      rescue JWT::ExpiredSignature
        # Handle expired token, e.g. logout user or deny access
        puts "Token expired thus redirecting to sso"
        redirect_to ENV["SSO_URL"] + "?app=" + ENV["MY_URL"]
      end
    else
      redirect_to ENV["SSO_URL"] + "?app=" + ENV["MY_URL"]
    end
    session[:user_id] = user.id
  end

  def current_user
    return @current_user if !@current_user.nil?
    if (user_id = session[:user_id])
      begin
        logger.debug "@@@@@@@@@@ CURRENT_USER before ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
        @current_user ||= User.find_by(id: user_id)
        logger.debug "@@@@@@@@@@ CURRENT_USER middle ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
      rescue Exception => e
        logger.debug "@@@@@@@@@@ Thread is sleeping RESCUE #{e} @@@@@@@@@@@@@@@@"
        ActiveRecord::Base.connection.close
        retry
      ensure
        logger.debug "@@@@@@@@@@ Thread in CURRENT_USER ENSURE @@@@@@@@@@@@@@@@"
        User.connection.close
        logger.debug "@@@@@@@@@@ CURRENT_USER ENSURE ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
      end
    elsif(user_id = cookies.signed[:user_id])
      begin
        user = User.find_by(id: user_id)
      rescue Exception => e
        logger.debug "@@@@@@@@@@ Thread is sleeping RESCUE #{e} @@@@@@@@@@@@@@@@"
      ensure
        logger.debug "@@@@@@@@@@ Thread in CURRENT_USER ENSURE @@@@@@@@@@@@@@@@"
        User.connection.close
        logger.debug "@@@@@@@@@@ CURRENT_USER ENSURE ==> #{ActiveRecord::Base.connection_pool.stat} @@@@@@@@@@@@@@@@"
      end
      if user && user.authenticated?(cookies[:remember_token])
        log_in user
        @current_user = user
      end
    end
    return @current_user
  end

end

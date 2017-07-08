class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  def dashboard
    if params[:token]
      hmac_secret = 'my$ecretK3y'
      begin
        decoded_token = JWT.decode params[:token], hmac_secret, true, { :algorithm => 'HS256' }
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
  end
end

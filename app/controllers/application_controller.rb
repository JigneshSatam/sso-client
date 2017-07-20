class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  include SessionsHelper
  def dashboard
    if params[:token]
      log_in(params[:token])
    else
      redirect_to ENV["SSO_URL"] + "?app=" + ENV["MY_URL"]
    end
  end
end

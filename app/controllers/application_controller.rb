class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  def dashboard
    @user = current_user
  end
end

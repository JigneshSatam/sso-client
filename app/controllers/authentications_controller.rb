class AuthenticationsController < ApplicationController
  def login
    if log_in(params[:token]) == true
      redirect_to root_url
    end
  end

  def logout
    log_out(params[:token])
    respond_to do |format|
      format.json {render json: nil, status: 200}
      format.html {redirect_to root_url}
    end
  end
end


Rails.application.routes.draw do
  resource :authentications do
    collection do
      get 'login'
      get 'logout'
      delete 'logout'
    end
  end

  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
  get "dashboard", to: "application#dashboard"

  root "application#dashboard"
end

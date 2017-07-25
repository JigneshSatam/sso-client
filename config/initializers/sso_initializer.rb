Rails.application.config.sso_settings = YAML::load(File.read(Rails.root.join("config", "sso_settings.yml")))[Rails.env]

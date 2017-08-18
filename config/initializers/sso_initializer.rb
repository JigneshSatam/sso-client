template = ERB.new File.read(Rails.root.join("config", "sso_settings.yml"))
Rails.application.config.sso_settings = YAML.load(template.result(binding))[Rails.env]
# Rails.application.config.sso_settings = YAML::load(File.read(Rails.root.join("config", "sso_settings.yml")))[Rails.env]

Rails.application.config.sso_settings = YAML::load(File.read(Rails.root.join("config", "sso_settings.yml")))[Rails.env]
# module SsoInitializer
#   module ClassMethods

#   end

#   module InstanceMethods

#   end

#   def self.included(receiver)
#     receiver.extend         ClassMethods
#     receiver.send :include, InstanceMethods
#   end
# end

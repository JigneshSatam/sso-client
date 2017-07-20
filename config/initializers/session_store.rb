# Be sure to restart your server when you modify this file.

# Rails.application.config.session_store :cookie_store, key: '_sso-client-alpha_session'

Rails.application.config.session_store :redis_store, servers: ["redis://localhost:6379/0/session"]

# :redis_store, {
#   servers: [
#     {
#       host: "localhost",
#       port: 6379,
#       db: 0,
#       password: "mysecret",
#       namespace: "session"
#     }
#   ],
#   expire_after: 90.minutes,
#   key: "_#{Rails.application.class.parent_name.downcase}_session"
# }


# redis cloud redis url
# REDISCLOUD_URL
# 30mb ==> 30 connections

# Heroku redis url
# REDIS_URL
# 25mb ==> 20 connections

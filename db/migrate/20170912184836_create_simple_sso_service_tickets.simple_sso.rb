# This migration comes from simple_sso (originally 20170829184029)
class CreateSimpleSsoServiceTickets < ActiveRecord::Migration[5.1]
  def change
    create_table :simple_sso_service_tickets do |t|
      t.integer :model_instance_id
      t.string :url
      t.string :session_id

      t.timestamps
    end
  end
end

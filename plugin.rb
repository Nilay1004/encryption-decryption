# frozen_string_literal: true

# name: encryption decryption
# about: Encrypt email before save in DB
# meta_topic_id: 123
# version: 0.0.1
# authors: Pankaj
# url: https://github.com/Nilay1004/discourse-plugin-test-basic
# required_version: 2.7.0

enabled_site_setting :plugin_name_enabled

# Avoid defining constants multiple times
unless defined?(::MyPluginModule)
  module ::MyPluginModule
    PLUGIN_NAME = "discourse-plugin-name-darshan"
  end
end

require_relative "lib/my_plugin_module/engine"

require 'net/http'
require 'uri'
require 'json'

after_initialize do
  Rails.logger.info "PIIEncryption: Plugin initialized"
  require_dependency 'user_email'

  module ::PIIEncryption
    def self.encrypt_email(email)
      return email if email.nil? || email.empty?

      uri = URI.parse("http://35.174.88.137:8080/encrypt")
      http = Net::HTTP.new(uri.host, uri.port)

      request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
      request.body = { data: email, pii_type: "email" }.to_json
      Rails.logger.info "PIIEncryption: Sending encryption request for email: #{email}"
      response = http.request(request)

      encrypted_email = JSON.parse(response.body)["encrypted_data"]
      Rails.logger.info "PIIEncryption: Encrypted email: #{encrypted_email}"
      encrypted_email
    rescue StandardError => e
      Rails.logger.error "Error encrypting email: #{e.message}"
      email
    end

    def self.hash_email(email)
      return email if email.nil? || email.empty?

      uri = URI.parse("http://35.174.88.137:8080/hash")
      http = Net::HTTP.new(uri.host, uri.port)

      request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
      request.body = { data: email, pii_type: "email" }.to_json
      Rails.logger.info "PIIEncryption: Sending hash request for email: #{email}"
      response = http.request(request)

      email_hash = JSON.parse(response.body)["hashed_data"]
      Rails.logger.info "PIIEncryption: Email hash: #{email_hash}"
      email_hash
    rescue StandardError => e
      Rails.logger.error "Error hashing email: #{e.message}"
      email
    end

    def self.decrypt_email(encrypted_email)
      return encrypted_email if encrypted_email.nil? || encrypted_email.empty?

      uri = URI.parse("http://35.174.88.137:8080/decrypt")
      http = Net::HTTP.new(uri.host, uri.port)

      request = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
      request.body = { data: encrypted_email }.to_json
      Rails.logger.info "PIIEncryption: Sending decryption request for encrypted email: #{encrypted_email}"
      response = http.request(request)

      decrypted_email = JSON.parse(response.body)["decrypted_data"]
      Rails.logger.info "PIIEncryption: Decrypted email: #{decrypted_email}"
      decrypted_email
    rescue StandardError => e
      Rails.logger.error "Error decrypting email: #{e.message}"
      encrypted_email
    end
  end

  class ::UserEmail
    before_validation :set_temporary_email_for_validation, if: :email_changed?
    after_validation :restore_encrypted_email, if: :email_changed?

    before_save :encrypt_email_address, if: :email_changed?

    def email
      @decrypted_email ||= PIIEncryption.decrypt_email(read_attribute(:email))
    end

    def email=(value)
      @decrypted_email = value
      encrypted_email = PIIEncryption.encrypt_email(value)
      email_hash = PIIEncryption.hash_email(value)
      write_attribute(:email, encrypted_email)
      write_attribute(:test_email, email_hash)
    end

    def decrypted_email
      PIIEncryption.decrypt_email(read_attribute(:email))
    end

    private

    def set_temporary_email_for_validation
      @original_email = read_attribute(:email)
      write_attribute(:email, @decrypted_email)
    end

    def restore_encrypted_email
      write_attribute(:email, @original_email)
    end

    def encrypt_email_address
      encrypted_email = PIIEncryption.encrypt_email(@decrypted_email)
      email_hash = PIIEncryption.hash_email(@decrypted_email)
      write_attribute(:email, encrypted_email)
      write_attribute(:test_email, email_hash)
    end
  end

  module ::PIIEncryption::UserPatch
    def email
      if new_record?
        read_attribute(:email)
      else
        PIIEncryption.decrypt_email(read_attribute(:email))
      end
    end

    def valid_email?(input_email)
      stored_hash = read_attribute(:test_email)
      input_hash = PIIEncryption.hash_email(input_email)
      Rails.logger.info "PIIEncryption: Comparing input hash #{input_hash} with stored hash #{stored_hash}"
      input_hash == stored_hash
    end
  end

  ::User.prepend(::PIIEncryption::UserPatch)

  # Override UserEmail uniqueness validation to use hashed email
  require_dependency 'email_validator'
  class ::EmailValidator
    def validate_each(record, attribute, value)
      if record.new_record? || record.will_save_change_to_attribute?(attribute)
        email_hash = PIIEncryption.hash_email(value)
        if UserEmail.where(test_email: email_hash).exists?
          record.errors.add(attribute, :taken)
        end
      end
    end
  end
end




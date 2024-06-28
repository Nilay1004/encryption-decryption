# frozen_string_literal: true

require_dependency 'user_serializer'

class UserSerializer < BasicUserSerializer
  attributes :decrypted_email

  def decrypted_email
    PIIEncryption.decrypt_email(object.email)
  end
end

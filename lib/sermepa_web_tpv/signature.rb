require 'digest'
require 'json'
require 'base64'
require 'openssl'

module SermepaWebTpv
  class Signature
    def self.signature_256(order_id, merchant_secret_key, merchant_parameters)
      order_signature = order_signature(order_id, merchant_secret_key)
      Base64.encode64(OpenSSL::HMAC.digest('sha256',Base64.encode64(order_signature.to_s),merchant_parameters))
    end

    private

    def self.order_signature(order_id, merchant_secret_key)
        cipher = OpenSSL::Cipher::Cipher.new("des-ede3")
        cipher.encrypt
        key = Base64.decode64(merchant_secret_key)
        iv = [0, 0, 0, 0, 0, 0, 0, 0].map { |e| e.chr }.join("")
        cipher.key = key
        cipher.iv = iv
        encrypted = cipher.update(order_id)
        encrypted << cipher.final
        signature = encrypted
        puts signature
        return signature
    end
  end
end

require 'digest'
require 'json'
require 'base64'
require 'openssl'

module SermepaWebTpv
  class Signature
    def self.signature_256(order_id, merchant_secret_key, merchant_parameters)
      order_signature = order_signature(order_id, merchant_secret_key)
      Base64.encode64(OpenSSL::HMAC.digest('sha256',order_signature,merchant_parameters))
    end

    private

    def self.order_signature(order_id, merchant_secret_key)
      des2 = OpenSSL::Cipher::Cipher.new('des-ede3')
      des2.encrypt
      des2.key = merchant_secret_key

      result = des2.update(order_id) + des2.final
      return Base64.encode64(result)
    end
  end
end

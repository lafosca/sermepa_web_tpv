require 'digest'
require 'openssl'
require 'base64'

module SermepaWebTpv
  class Response < Struct.new(:params)
    def valid?
      params[:Ds_Signature] == signature
    end

    def success?
      params[:Ds_Response].to_i == 0
    end

    private
    def signature
      merchant_params = JSON.parse(Base64.decode64(params[:Ds_MerchantParameters]), symbolize_names: true);

      secure = (merchant_params[:Ds_Terminal].to_i == SermepaWebTpv.secure_terminal)
      secret_key = secure ? SermepaWebTpv.merchant_secure_secret_key : SermepaWebTpv.merchant_secret_key

      Signature.signature_256(merchant_params[:Ds_Order].to_s, secret_key , params[:Ds_MerchantParameters])
    end

    def signature_256
      merchant_secret_key = secure ? SermepaWebTpv.merchant_secure_secret_key : SermepaWebTpv.merchant_secret_key
      order_id = transaction_number.to_s

      des2 = OpenSSL::Cipher::Cipher.new('des-ede3')
      des2.encrypt
      des2.key = merchant_secret_key

      result = des2.update(order_id) + des2.final
      return Base64.encode64(result)
    end

    def transaction_number
      request_params[:Ds_Merchant_Order]
    end

    def request_params
        request_string = Base64.decode64(params[:Ds_MerchantParameters])
        if request_string.length > 0
          params = JSON.parse(request_string)
        else
          return nil
        end
    end
  end
end

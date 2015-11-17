require 'digest'
require 'openssl'
require 'base64'

module SermepaWebTpv
  class Response < Struct.new(:params)
    def valid?
      params[:Ds_Signature] == signature
    end

    def success?
      merchant_parameters[:Ds_Response].to_i == 0
    end

    def merchant_parameters
      JSON.parse(Base64.decode64(params[:Ds_MerchantParameters]), symbolize_names: true)
    end

    private
    def signature
      merchant_params = merchant_parameters

      secure = (merchant_params[:Ds_Terminal].to_i == SermepaWebTpv.secure_terminal)
      secret_key = secure ? SermepaWebTpv.merchant_secure_secret_key : SermepaWebTpv.merchant_secret_key

      Signature.signature_256(merchant_params[:Ds_Order].to_s, secret_key , params[:Ds_MerchantParameters])
    end
  end
end

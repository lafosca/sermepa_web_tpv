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

      sig = Signature.signature_256(merchant_params[:Ds_Order].to_s, secret_key , params[:Ds_MerchantParameters])

      # Here is the new 'magic' for Sermepa
      # We MUST replace '+' with '-'
      # We MUST replace '/' with '_'
      # Maybe they use this signature in some GET route, or something like that
      # And they return it with this characters replaced
      # As seen in https://gist.github.com/enoliglesias/7d01a443700f9bb94752
      sig.gsub("+", "-").gsub("/", "_")
    end
  end
end

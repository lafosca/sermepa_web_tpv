require 'digest/sha1'

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
      secure = (params[:Ds_Terminal].to_i == SermepaWebTpv.secure_terminal)

      secret_key = secure ? SermepaWebTpv.merchant_secure_secret_key : SermepaWebTpv.merchant_secret_key

      response = %W(
        #{params[:Ds_Amount]}
        #{params[:Ds_Order]}
        #{params[:Ds_MerchantCode]}
        #{params[:Ds_Currency]}
        #{params[:Ds_Response]}
        #{secret_key}
      ).join
      Digest::SHA1.hexdigest(response).upcase
    end
  end
end
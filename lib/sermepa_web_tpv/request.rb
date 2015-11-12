require 'uri'
require 'digest'
require 'json'
require 'base64'
require 'openssl'

module SermepaWebTpv
  class Request < Struct.new(:transaction, :description)
    include SermepaWebTpv::Persistence::ActiveRecord

    def bank_url
      SermepaWebTpv.bank_url
    end

    def options
      must_options
    end

    def options_with_reference(reference="", secure=true)
      must_options(reference, secure)
    end

    def transact(&block)
      generate_transaction_number!
      yield(transaction)
      self
    end

    def optional_options
      {
        'Ds_Merchant_Titular'      => SermepaWebTpv.merchant_name,
        'Ds_Merchant_UrlKO'        => url_for(:redirect_failure_path),
        'Ds_Merchant_UrlOK'        => url_for(:redirect_success_path)
      }.delete_if {|key, value| value.blank? }
    end

    private

    def transaction_number_attribute
      SermepaWebTpv.transaction_model_transaction_number_attribute
    end

    def transaction_model_amount_attribute
      SermepaWebTpv.transaction_model_amount_attribute
    end

    def amount
      (transaction_amount * 100).to_i.to_s
    end

    def must_options(reference="", secure=true)
      merchant_secret_key = secure ? SermepaWebTpv.merchant_secure_secret_key : SermepaWebTpv.merchant_secret_key

      options_hash = {
        'Ds_MerchantParameters' => merchant_parameters,
        'Ds_Signature' =>  Signature.signature_256(transaction_number, merchant_secret_key , merchant_parameters),
        'Ds_SignatureVersion' => "HMAC_SHA256_V1"
      }
      options_hash
    end

    def signature(reference="REQUIRED",secure=true)
      #Ds_Merchant_Amount + Ds_Merchant_Order +Ds_Merchant_MerchantCode + Ds_Merchant_Currency +Ds_Merchant_TransactionType + Ds_Merchant_MerchantURL + CLAVE SECRETA
      merchant_code = SermepaWebTpv.merchant_code
      currency = SermepaWebTpv.currency
      transaction_type = SermepaWebTpv.transaction_type
      callback_url = url_for(:callback_response_path)

      merchant_secret_key = secure ? SermepaWebTpv.merchant_secure_secret_key : SermepaWebTpv.merchant_secret_key

      if reference != "REQUIRED"
          direct_payment = SermepaWebTpv.direct_payment ? "true" : ""
          return Digest::SHA256.hexdigest("#{amount}#{transaction_number}#{merchant_code}#{currency}#{transaction_type}#{callback_url}#{reference}#{direct_payment}#{merchant_secret_key}").upcase

      end

      Digest::SHA256.hexdigest("#{amount}#{transaction_number}#{merchant_code}#{currency}#{transaction_type}#{callback_url}#{reference}#{merchant_secret_key}").upcase
    end

    def options_for_signature(reference="", secure=true)
      options_hash = {
        'Ds_Merchant_Amount' =>             amount,
        'Ds_Merchant_Currency' =>           SermepaWebTpv.currency, #EURO
        'Ds_Merchant_Order' =>              transaction_number,
        'Ds_Merchant_ProductDescription' => description,
        'Ds_Merchant_MerchantCode' =>       SermepaWebTpv.merchant_code,
        'Ds_Merchant_Terminal' =>           secure ? SermepaWebTpv.secure_terminal : SermepaWebTpv.terminal,
        'Ds_Merchant_TransactionType' =>    SermepaWebTpv.transaction_type,
        'Ds_Merchant_ConsumerLanguage' =>   SermepaWebTpv.language,
        'Ds_Merchant_MerchantURL' =>        url_for(:callback_response_path)
      }

      if reference && reference != ""
        options_hash['Ds_Merchant_Identifier'] = reference

        if reference!= "REQUIRED" && SermepaWebTpv.direct_payment
          options_hash['Ds_Merchant_DirectPayment'] = "true"
        end
      end

      optional_options.merge(options_hash)
    end

    def merchant_parameters
      Base64.encode64(options_for_signature.to_json)
    end

    # Available options
    # redirect_success_path
    # redirect_failure_path
    # callback_response_path
    def url_for(option)
      host = SermepaWebTpv.response_host
      path = SermepaWebTpv.send(option)

      if host.present? && path.present?
        URI.join("http://#{host}", path).to_s
      end
    end
  end
end

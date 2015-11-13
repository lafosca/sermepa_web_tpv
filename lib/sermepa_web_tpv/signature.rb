require 'digest'
require 'json'
require 'base64'
require 'openssl'

module SermepaWebTpv
  class Signature
    def self.signature_256(order_id, merchant_secret_key, merchant_parameters)
      key_des3 = order_signature(order_id, merchant_secret_key)
      # The next step is to encrypt in SHA256 the resulting des3 key with the base64 json
      result = OpenSSL::HMAC.digest('sha256', key_des3, merchant_parameters)
      # The last step is to encode the data in base64
      Base64.strict_encode64(result)
    end

    private

    def self.order_signature(order_id, merchant_secret_key)
      # By default OpenSSL generates an all-zero array for the encriptation vector
      # You can read it here: http://ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/Cipher.html#method-i-iv-3D
      # If you want to declare it, you can take a look at the next couple of lines
      #bytes = Array.new(8,0)
      #iv = bytes.map(&:chr).join
      # We need to decode the secret key
      key = Base64.strict_decode64(merchant_secret_key)
      # In thee cipher initialization we need to speficy the encryptation like method-length-mode (http://ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/Cipher.html#method-c-new).
      # Sermepa needs DES3 in CBC mode
      # The direct way the declare it's: des-ede3-cbc
      # You can also declare like 'des3' wich use CBC mode by default
      des3 = OpenSSL::Cipher::Cipher.new('des-ede3-cbc')
      # OpenSSL use by default PKCS padding. But Sermepa (mcrypt_encrypt PHP function) use zero padding.
      # OpenSSL do not allow zero padding. So we need to disable the default padding and make zero padding by hand
      # Padding in cryptography is to fill the data with especial characteres in order to use the data in blocks of N (https://en.wikipedia.org/wiki/Padding_(cryptography))
      # We need to use blocks of 8 bytes
      block_length = 8
      # We tell OpenSSL not to pad
      des3.padding = 0
      # We want to encrypt
      des3.encrypt
      # Key set
      des3.key = key
      #des3.iv = iv
      data = order_id
      # Here is the 'magic'. Instead use the default OpenSSL padding (PKCS). We fill with \0 till the data have
      # a multiple of the block size (8, 16, 24...)
      data += "\0" until data.bytesize % block_length == 0
      # For example: the string "123456789" will be transform in "123456789\x00\x00\x00\x00\x00\x00\x00"
      # data must be in blocks of 8 or the update will break
      des3.update(data) + des3.final
    end
  end
end

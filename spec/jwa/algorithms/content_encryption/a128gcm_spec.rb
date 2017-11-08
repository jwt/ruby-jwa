require_relative './aes_gcm_shared'

# Test vector from http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
describe JWA::Algorithms::ContentEncryption::A128gcm do
  include_examples 'AES-GCM' do
    let(:plaintext) do
      hex_string_to_bytes('08000F101112131415161718191A1B1C
                           1D1E1F202122232425262728292A2B2C
                           2D2E2F303132333435363738393A3B3C
                           3D3E3F404142434445464748490008')
    end

    let(:authenticated_data) do
      hex_string_to_bytes('68F2E77696CE7AE8E2CA4EC588E54D002E58495C')
    end

    let(:key) do
      hex_string_to_bytes('88EE087FD95DA9FBF6725AA9D757B0CD')
    end

    let(:iv) do
      hex_string_to_bytes('7AE8E2CA4EC500012E58495C')
    end

    let(:ciphertext) do
      hex_string_to_bytes('C31F53D99E5687F7365119B832D2AAE7
                           0741D593F1F9E2AB3455779B078EB8FE
                           ACDFEC1F8E3E5277F8180B43361F6512
                           ADB16D2E38548A2C719DBA7228D840')
    end

    let(:tag) do
      hex_string_to_bytes('88F8757ADB8AA788D8F65AD668BE70E7')
    end
  end
end

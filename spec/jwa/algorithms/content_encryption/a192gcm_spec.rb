require_relative './aes_gcm_shared'

# Test vector from http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.694.695&rep=rep1&type=pdf
describe JWA::Algorithms::ContentEncryption::A192gcm do
  include_examples 'AES-GCM' do
    let(:plaintext) do
      hex_string_to_bytes(
        'd9313225f88406e5a55909c5aff5269a
         86a7a9531534f7da2e4c303d8a318a72
         1c3c0c95956809532fcf0e2449a6b525
         b16aedf5aa0de657ba637b39'
      )
    end

    let(:authenticated_data) do
      hex_string_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2')
    end

    let(:key) do
      hex_string_to_bytes(
        'feffe9928665731c6d6a8f9467308308
         feffe9928665731c'
      )
    end

    let(:iv) do
      hex_string_to_bytes('cafebabefacedbaddecaf888')
    end

    let(:ciphertext) do
      hex_string_to_bytes(
        '3980ca0b3c00e841eb06fac4872a2757
         859e1ceaa6efd984628593b40ca1e19c
         7d773d00c144c525ac619d18c84a3f47
         18e2448b2fe324d9ccda2710'
      )
    end

    let(:tag) do
      hex_string_to_bytes('2519498e80f1478f37ba55bd6d27618c')
    end
  end
end

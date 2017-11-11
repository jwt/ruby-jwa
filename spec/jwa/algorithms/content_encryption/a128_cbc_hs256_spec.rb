require_relative './aes_cbc_hs_shared'

describe JWA::Algorithms::ContentEncryption::A128CbcHs256 do
  include_examples 'AES-CBC-HS' do
    let(:key) do
      '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
       10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f'
    end

    let(:ciphertext) do
      'c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79
       a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9
       a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2
       fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36
       09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8
       6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b
       38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f
       bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5
       4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db'
    end

    let(:tag) { '65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4' }
  end

  describe '.enc_name' do
    it 'equals A128CBC-HS256' do
      expect(described_class.enc_name).to eq 'A128CBC-HS256'
    end
  end
end

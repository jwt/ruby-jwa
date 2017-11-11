require_relative './aes_cbc_hs_shared'

describe JWA::Algorithms::ContentEncryption::A256CbcHs512 do
  include_examples 'AES-CBC-HS' do
    let(:key) do
      '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
       10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
       20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
       30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f'
    end

    let(:ciphertext) do
      '4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd
       3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd
       82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2
       e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b
       36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1
       1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3
       a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e
       31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b
       be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6'
    end

    let(:tag) do
      '4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf
       2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5'
    end
  end

  describe '.enc_name' do
    it 'equals A256CBC-HS512' do
      expect(described_class.enc_name).to eq 'A256CBC-HS512'
    end
  end
end

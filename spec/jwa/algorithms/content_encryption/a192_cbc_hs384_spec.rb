require_relative './aes_cbc_hs_shared'

describe JWA::Algorithms::ContentEncryption::A192CbcHs384 do
  include_examples 'AES-CBC-HS' do
    let(:key) do
      '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
       10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
       20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f'
    end

    let(:ciphertext) do
      'ea 65 da 6b 59 e6 1e db 41 9b e6 2d 19 71 2a e5
       d3 03 ee b5 00 52 d0 df d6 69 7f 77 22 4c 8e db
       00 0d 27 9b dc 14 c1 07 26 54 bd 30 94 42 30 c6
       57 be d4 ca 0c 9f 4a 84 66 f2 2b 22 6d 17 46 21
       4b f8 cf c2 40 0a dd 9f 51 26 e4 79 66 3f c9 0b
       3b ed 78 7a 2f 0f fc bf 39 04 be 2a 64 1d 5c 21
       05 bf e5 91 ba e2 3b 1d 74 49 e5 32 ee f6 0a 9a
       c8 bb 6c 6b 01 d3 5d 49 78 7b cd 57 ef 48 49 27
       f2 80 ad c9 1a c0 c4 e7 9c 7b 11 ef c6 00 54 e3'
    end

    let(:tag) do
      '84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20
       75 16 80 39 cc c7 33 d7'
    end
  end

  describe '.enc_name' do
    it 'equals A192CBC-HS384' do
      expect(described_class.enc_name).to eq 'A192CBC-HS384'
    end
  end
end

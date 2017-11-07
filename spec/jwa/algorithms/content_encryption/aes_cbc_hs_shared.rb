shared_examples 'AES-CBC-HS' do
  let(:plaintext) do
    '41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
     6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
     69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
     74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
     65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
     6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
     20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
     75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65'
  end

  let(:authenticated_data) do
    '54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
     69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
     4b 65 72 63 6b 68 6f 66 66 73'
  end

  let(:iv) { '1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04' }

  let(:b_plaintext) { hex_string_to_bytes(plaintext) }
  let(:b_authenticated_data) { hex_string_to_bytes(authenticated_data) }
  let(:b_key) { hex_string_to_bytes(key) }
  let(:b_iv) { hex_string_to_bytes(iv) }
  let(:b_ciphertext) { hex_string_to_bytes(ciphertext) }
  let(:b_tag) { hex_string_to_bytes(tag) }

  subject { described_class.new(b_key, b_iv) }

  it 'encrypts according to RFC7518' do
    ciphertext, tag = subject.encrypt(b_plaintext, b_authenticated_data)

    expect(ciphertext).to eq(b_ciphertext)
    expect(tag).to eq(b_tag)
  end

  it 'decrypt according to RFC7518' do
    plaintext = subject.decrypt(b_ciphertext, b_authenticated_data, b_tag)

    expect(plaintext).to eq(b_plaintext)
  end

  it 'raises when provided a wrong key size' do
    expect do
      described_class.new(b_key + "\x00", b_iv)
    end.to raise_error(JWA::InvalidKey)
  end

  it 'raises when provided a wrong iv size' do
    expect do
      described_class.new(b_key, b_iv + "\x00")
    end.to raise_error(JWA::InvalidIV)
  end

  it 'exposes the used key' do
    expect(subject.key).to eq b_key
  end

  it 'exposes the used iv' do
    ins = described_class.new(b_key)
    expect(ins.iv).to_not be_nil
  end

  describe '#available?' do
    context 'when the cipher is not available' do
      it 'is false' do
        allow(JWA::Cipher).to receive(:for) { raise NotImplementedError }
        expect(described_class.available?).to be_falsey
      end
    end

    context 'when the cipher is available' do
      it 'is true' do
        allow(JWA::Cipher).to receive(:for)
        expect(described_class.available?).to be_truthy
      end
    end
  end

  it 'raises an error if the tag is corrupt' do
    expect do
      subject.decrypt(b_ciphertext, b_authenticated_data, 'random data')
    end.to raise_error(JWA::BadDecrypt)
  end

  it 'raises an error if the signature pass, but decryption fails' do
    # The second half of the key influcences only decryption, but not signature checking
    key = b_key.dup
    key[-1] = "\x00"

    ins = described_class.new(key, b_iv)
    expect do
      ins.decrypt(b_ciphertext, b_authenticated_data, b_tag)
    end.to raise_error(JWA::BadDecrypt)
  end
end

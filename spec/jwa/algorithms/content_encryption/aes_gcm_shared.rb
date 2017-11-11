shared_examples 'AES-GCM' do
  subject { described_class.new(key, iv) }

  it 'encrypts according to the Test Case' do
    r_ciphertext, r_tag = subject.encrypt(plaintext, authenticated_data)

    expect(r_ciphertext).to eq(ciphertext)
    expect(r_tag).to eq(tag)
  end

  it 'decrypt according to the Test Case' do
    r_plaintext = subject.decrypt(ciphertext, authenticated_data, tag)

    expect(r_plaintext).to eq(plaintext)
  end

  it 'raises when provided a wrong key size' do
    expect do
      described_class.new(key + "\x00", iv)
    end.to raise_error(ArgumentError)
  end

  it 'raises when provided a wrong iv size' do
    expect do
      described_class.new(key, iv + "\x00")
    end.to raise_error(ArgumentError)
  end

  it 'exposes the used key' do
    expect(subject.key).to eq key
  end

  it 'exposes the used iv' do
    ins = described_class.new(key)
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

  it 'raises an error if decryption fails' do
    ins = described_class.new("\x00" * described_class.key_length, iv)
    expect do
      ins.decrypt(ciphertext, authenticated_data, tag)
    end.to raise_error(JWA::BadDecrypt)
  end
end

describe JWA::Algorithms::KeyManagement::A128Kw do
  let(:jwk) { JWK::Key.from_json(File.read('spec/support/oct16.json')) }

  let(:plaintext) do
    int_byte_array_to_bytes([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
                             206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
                             44, 207])
  end

  let(:ciphertext) do
    int_byte_array_to_bytes([232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216,
                             22, 67, 201, 138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3,
                             76, 124, 193, 11, 98, 37, 173, 61, 104, 57])
  end

  it 'decrypts according to the Test Case (RFC 7516 - Section A.3)' do
    key = jwk.to_s

    alg = described_class.new(key)
    expect(alg.decrypt(ciphertext)).to eq plaintext
  end

  it 'encrypts according to the Test Case' do
    key = jwk.to_s

    alg = described_class.new(key)
    expect(alg.encrypt(plaintext)).to eq ciphertext
  end

  it 'raises when the iv doesn\'t match' do
    key = jwk.to_s

    alg = described_class.new(key)
    ciph = alg.encrypt(plaintext)

    alg2 = described_class.new(key, "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5")
    expect { alg2.decrypt(ciph) }.to raise_error(StandardError)
  end

  it 'raises for wrong key sizes' do
    expect { described_class.new("\x00" * 12) }.to raise_error(JWA::InvalidKey)
  end
end

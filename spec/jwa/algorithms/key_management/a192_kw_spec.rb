describe JWA::Algorithms::KeyManagement::A192Kw do
  let(:jwk) { JWK::Key.from_json(File.read('spec/support/oct24.json')) }

  let(:plaintext) do
    int_byte_array_to_bytes([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
                             206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
                             44, 207])
  end

  let(:ciphertext) do
    int_byte_array_to_bytes([143, 218, 154, 233, 170, 149, 194, 128, 166, 3, 246, 159, 78, 90, 167,
                             0, 22, 179, 29, 231, 11, 77, 104, 42, 102, 115, 158, 61, 247, 117,
                             234, 19, 241, 102, 103, 177, 218, 215, 160, 151])
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
end

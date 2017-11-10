describe JWA::Algorithms::KeyManagement::A256Kw do
  let(:jwk) { JWK::Key.from_json(File.read('spec/support/oct32.json')) }

  let(:plaintext) do
    int_byte_array_to_bytes([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
                             206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
                             44, 207])
  end

  let(:ciphertext) do
    int_byte_array_to_bytes([198, 158, 179, 0, 33, 254, 44, 72, 227, 132, 72, 122, 1, 139, 110, 8,
                             55, 39, 196, 203, 65, 90, 255, 20, 27, 211, 159, 146, 66, 122, 239, 238,
                             145, 174, 248, 60, 215, 107, 251, 14])
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

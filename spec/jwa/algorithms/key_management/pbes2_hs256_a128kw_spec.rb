describe JWA::Algorithms::KeyManagement::Pbes2Hs256A128Kw do
  let(:password) { 'Thus from my lips, by yours, my sin is purged.' }
  let(:salt) { int_byte_array_to_bytes([217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215]) }
  let(:iterations) { 4096 }

  let(:plaintext) do
    int_byte_array_to_bytes([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112,
                             161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48,
                             253, 182])
  end

  let(:ciphertext) do
    int_byte_array_to_bytes([78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134,
                             188, 66, 125, 36, 200, 222, 124, 5, 103, 249, 52, 117, 184, 140, 81,
                             246, 158, 161, 177, 20, 33, 245, 57, 59, 4])
  end

  it 'decrypts according to the Test Case (RFC 7517 - Appendix C)' do
    alg = described_class.new(password, salt, iterations)
    expect(alg.decrypt(ciphertext)).to eq plaintext
  end

  it 'encrypts according to the Test Case' do
    alg = described_class.new(password, salt, iterations)
    expect(alg.encrypt(plaintext)).to eq ciphertext
  end
end

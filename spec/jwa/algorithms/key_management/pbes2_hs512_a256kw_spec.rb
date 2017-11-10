# WARNING:
#   No public test case was found, so this was artificially generated.
#   The ciphertext here is what I expect it to be, not what is known to be correct.
#   Hopefully it's still correct

describe JWA::Algorithms::KeyManagement::Pbes2Hs512A256Kw do
  let(:password) { 'Thus from my lips, by yours, my sin is purged.' }
  let(:salt) { int_byte_array_to_bytes([217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215]) }
  let(:iterations) { 4096 }

  let(:plaintext) do
    int_byte_array_to_bytes([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112,
                             161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48,
                             253, 182])
  end

  let(:ciphertext) do
    int_byte_array_to_bytes([39, 197, 106, 80, 194, 86, 68, 142, 208, 178, 205, 219, 128, 6, 150,
                             128, 95, 89, 173, 74, 146, 122, 27, 6, 246, 140, 179, 235, 92, 116,
                             188, 38, 248, 145, 218, 221, 14, 245, 131, 159])
  end

  it 'decrypts predictably' do
    alg = described_class.new(password, salt, iterations)
    expect(alg.decrypt(ciphertext)).to eq plaintext
  end

  it 'encrypts predictably' do
    alg = described_class.new(password, salt, iterations)
    expect(alg.encrypt(plaintext)).to eq ciphertext
  end
end

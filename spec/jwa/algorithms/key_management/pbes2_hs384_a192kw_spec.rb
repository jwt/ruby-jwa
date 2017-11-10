# WARNING:
#   No public test case was found, so this was artificially generated.
#   The ciphertext here is what I expect it to be, not what is known to be correct.
#   Hopefully it's still correct

describe JWA::Algorithms::KeyManagement::Pbes2Hs384A192Kw do
  let(:password) { 'Thus from my lips, by yours, my sin is purged.' }
  let(:salt) { int_byte_array_to_bytes([217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215]) }
  let(:iterations) { 4096 }

  let(:plaintext) do
    int_byte_array_to_bytes([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112,
                             161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48,
                             253, 182])
  end

  let(:ciphertext) do
    int_byte_array_to_bytes([215, 56, 252, 107, 109, 188, 15, 220, 217, 9, 142, 195, 65, 53, 139,
                             56, 180, 25, 68, 130, 147, 127, 238, 100, 239, 217, 250, 240, 70, 8,
                             35, 18, 242, 142, 239, 238, 250, 130, 221, 180])
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

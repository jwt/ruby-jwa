describe JWA::Algorithms::KeyManagement::EcdhEs do
  let(:alice) { JWK::Key.from_json(File.read('spec/support/ec1.json')) }
  let(:bob) { JWK::Key.from_json(File.read('spec/support/ec2.json')) }

  let(:expected) do
    int_byte_array_to_bytes([86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26])
  end

  it 'resolves alice\'s key according to the spec' do
    alg = described_class.new(alice.to_openssl_key, 16, 'A128GCM', 'Alice', 'Bob')
    expect(alg.encrypt(bob.to_openssl_key.public_key)).to eq expected
  end

  it 'resolves bob\'s key according to the spec' do
    alg = described_class.new(bob.to_openssl_key, 16, 'A128GCM', 'Alice', 'Bob')
    expect(alg.encrypt(alice.to_openssl_key.public_key)).to eq expected
  end
end

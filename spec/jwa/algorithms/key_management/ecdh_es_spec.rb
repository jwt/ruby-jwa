describe JWA::Algorithms::KeyManagement::EcdhEs do
  let(:alice) { JWK::Key.from_json(File.read('spec/support/ec1.json')) }
  let(:bob) { JWK::Key.from_json(File.read('spec/support/ec2.json')) }

  let(:expected) do
    int_byte_array_to_bytes([86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26])
  end

  it 'resolves alice\'s key according to the spec' do
    alg = described_class.new(alice.to_openssl_key, 16, 'A128GCM', 'Alice', 'Bob')

    begin
      actual = alg.encrypt(bob.to_openssl_key.public_key)
      expect(actual).to eq expected
    rescue Exception => e
      raise e unless defined?(JRUBY_VERSION)

      $stderr.puts('WARNING: This test fails on jRuby due to incorrect EC Keys implementation. It would still work ' +
                   'if the OpenSSL keys were generated instead of loaded.')
    end
  end

  it 'resolves bob\'s key according to the spec' do
    alg = described_class.new(bob.to_openssl_key, 16, 'A128GCM', 'Alice', 'Bob')

    begin
      actual = alg.encrypt(alice.to_openssl_key.public_key)
      expect(actual).to eq expected
    rescue Exception => e
      raise e unless defined?(JRUBY_VERSION)

      $stderr.puts('WARNING: This test fails on jRuby due to incorrect EC Keys implementation. It would still work ' +
                   'if the OpenSSL keys were generated instead of loaded.')
    end
  end
end

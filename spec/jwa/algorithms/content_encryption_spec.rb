describe JWA::Algorithms::ContentEncryption do
  describe '.for' do
    it 'returns a class for a given encryption method name' do
      expect(described_class.for('A128GCM')).to be JWA::Algorithms::ContentEncryption::A128Gcm
    end
  end
end

describe JWA::Algorithms::KeyManagement do
  describe '.for' do
    it 'returns a class for a given key management method name' do
      expect(described_class.for('A256KW')).to be JWA::Algorithms::KeyManagement::A256Kw
    end
  end
end

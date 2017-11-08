describe JWA::Cipher do
  it 'raises if the cipher does not exist (or is not supported by this ruby)' do
    expect do
      JWA::Cipher.for('very-strange-cipher')
    end.to raise_error(NotImplementedError)
  end
end

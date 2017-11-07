describe JWA::Cipher do
  it 'raises if the cipher does not exist (or is not supported by this ruby)' do
    expect do
      JWA::Cipher.for('aes-257-cbc')
    end.to raise_error(NotImplementedError)
  end
end

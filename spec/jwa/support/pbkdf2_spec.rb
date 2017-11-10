describe JWA::Support::PBKDF2 do
  test_cases = [
    {
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 1,
      key_length: 16,
      expected: 'cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15'
    },
    {
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 1,
      key_length: 32,
      expected: 'cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15 0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37'
    },
    {
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 2,
      key_length: 16,
      expected: '01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d'
    },
    {
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 2,
      key_length: 32,
      expected: '01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86'
    },
    {
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 1200,
      key_length: 16,
      expected: '5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b'
    },
    {
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 1200,
      key_length: 32,
      expected: '5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13'
    },
    {
      password: 'password',
      salt: [0x1234567878563412].pack('Q'),
      iterations: 5,
      key_length: 16,
      expected: 'd1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49'
    },
    {
      password: 'password',
      salt: [0x1234567878563412].pack('Q'),
      iterations: 5,
      key_length: 32,
      expected: 'd1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49 3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee'
    },
    {
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase equals block size',
      iterations: 1200,
      key_length: 16,
      expected: '13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9'
    },
    {
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase equals block size',
      iterations: 1200,
      key_length: 32,
      expected: '13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9 c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1'
    },
    {
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase exceeds block size',
      iterations: 1200,
      key_length: 16,
      expected: '9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61'
    },
    {
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase exceeds block size',
      iterations: 1200,
      key_length: 32,
      expected: '9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61 1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a'
    },
    {
      password: [0xf09d849e].pack('N'),
      salt: 'EXAMPLE.COMpianist',
      iterations: 50,
      key_length: 16,
      expected: '6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39'
    },
    {
      password: [0xf09d849e].pack('N'),
      salt: 'EXAMPLE.COMpianist',
      iterations: 50,
      key_length: 32,
      expected: '6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39 e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52'
    }
  ]

  test_cases.each_with_index do |params, i|
    subject { described_class.new(OpenSSL::Digest::SHA1.new) }

    it "derives according to test case #{i + 1} of RFC 3962" do
      expected = params[:expected].delete(' ')
      expect(subject.run_hex(params[:password], params[:salt], params[:iterations], params[:key_length])).to eq expected
    end
  end
end

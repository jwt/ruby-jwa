# WARNING:
#   The only publicly known test case I could find involves is only about deriving
#   a 128-bit Key from a SHA256 hash.
#
#   This means that my implementation is only tested against SHA256 and for key
#   size less than or equal to 256 bits (and incidentally, with a single round
#   of the KDF function).
#
#   This test case comes from JWE RFC 7518 Appendix C.

describe JWA::Support::ConcatKDF do
  test_cases = [
    {
      hash: OpenSSL::Digest::SHA256.new,
      z: [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
          38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
          140, 254, 144, 196].map(&:chr).join,
      info: [0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
             99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128].map(&:chr).join,
      key_length: 128,
      expected: [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26].map(&:chr).join
    }
  ]

  test_cases.each_with_index do |params, i|
    subject { described_class.new(params[:hash]) }

    it "derives according to test case #{i + 1}" do
      expect(subject.run(params[:z], params[:info], params[:key_length])).to eq params[:expected]
    end
  end
end

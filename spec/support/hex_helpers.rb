module HexHelpers
  def hex_string_to_bytes(s)
    s.scan(/[0-9a-f]{2}/i).map { |pair| pair.to_i(16).chr }.join
  end

  def int_byte_array_to_bytes(a)
    a.map(&:chr).join
  end
end

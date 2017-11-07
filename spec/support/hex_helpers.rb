module HexHelpers
  def hex_string_to_bytes(s)
    s.split(/\s+/).map { |pair| pair.to_i(16).chr }.join
  end
end

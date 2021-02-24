# hash.rb
def ror i, bits = 13
  ((i >> bits) | (i << (32 - bits))) & 0xFFFFFFFF
end
def hash mod, func
  mod_hash = "#{mod.upcase.b}\x00"
    .encode('utf-16le')
    .unpack('C*')
    .inject(0){|h, i| ror(h) + i}
  func_hash = "#{func.b}\x00"
    .unpack('C*')
    .inject(0){|h, i| ror(h) + i}
  (mod_hash + func_hash) & 0xFFFFFFFF
end
mod, func = *ARGV
puts('0x%08X = %s!%s' % [hash(mod, func), mod, func])
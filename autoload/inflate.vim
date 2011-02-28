" [DEFLATE Compressed Data Format Specification version 1.3]
" http://www.ietf.org/rfc/rfc1951.txt
" [DEFLATE] (description in Japanese)
" http://www.river.sannet.ne.jp/yuui/fileformat/deflate1.html
" Last Change:  2011-03-01
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
" License:      This file is placed in the public domain.

function inflate#inflate(data)
  return s:Inflate.new(a:data).inflate()
endfunction

let s:BTYPE_NO_COMPRESSION = 0
let s:BTYPE_FIXED_HUFFMAN = 1
let s:BTYPE_DYNAMIC_HUFFMAN = 2
let s:BTYPE_RESERVED = 3

let s:Inflate = {}

" generated later
let s:Inflate.fixed_lit_code = {}
let s:Inflate.fixed_dist_code = {}

" value => [len, extra_bits]
let s:Inflate.len_extra_bits = {
      \ '257':[3,0], '258':[4,0], '259':[5,0], '260':[6,0],
      \ '261':[7,0], '262':[8,0], '263':[9,0], '264':[10,0],
      \ '265':[11,1], '266':[13,1], '267':[15,1], '268':[17,1],
      \ '269':[19,2], '270':[23,2], '271':[27,2], '272':[31,2],
      \ '273':[35,3], '274':[43,3], '275':[51,3], '276':[59,3],
      \ '277':[67,4], '278':[83,4], '279':[99,4], '280':[115,4],
      \ '281':[131,5], '282':[163,5], '283':[195,5], '284':[227,5],
      \ '285':[258,0],
      \ }

" value => [len, extra_bits]
let s:Inflate.dist_extra_bits = {
      \ '0':[1,0], '1':[2,0], '2':[3,0], '3':[4,0],
      \ '4':[5,1], '5':[7,1], '6':[9,2], '7':[13,2],
      \ '8':[17,3], '9':[25,3], '10':[33,4], '11':[49,4],
      \ '12':[65,5], '13':[97,5], '14':[129,6], '15':[193,6],
      \ '16':[257,7], '17':[385,7], '18':[513,8], '19':[769,8],
      \ '20':[1025,9], '21':[1537,9], '22':[2049,10], '23':[3073,10],
      \ '24':[4097,11], '25':[6145,11], '26':[8193,12], '27':[12289,12],
      \ '28':[16385,13], '29':[24577,13],
      \ }

function s:Inflate.new(data)
  let obj = deepcopy(s:Inflate)
  call obj.__init__(a:data)
  return obj
endfunction

function s:Inflate.__init__(data)
  let self.stream = s:Bitstream.new(a:data)
  let self.out = []
endfunction

function s:Inflate.inflate()
  while 1
    let bfinal = self.stream.readint(1)
    let btype = self.stream.readint(2)
    if btype == s:BTYPE_RESERVED
      throw "BTYPE_RESERVED"
    endif
    if btype == s:BTYPE_NO_COMPRESSION
      call self.stream.skip_to_byte_align()
      let len = self.stream.readint(16)
      let nlen = self.stream.readint(16)
      let self.out += self.stream.readbytes(len)
    else
      let lit_code = self.fixed_lit_code
      let dist_code = self.fixed_dist_code
      if btype == s:BTYPE_DYNAMIC_HUFFMAN
        let [lit_code, dist_code] = self.read_custom_code()
      endif
      while 1
        let value = self.read_code(lit_code)
        if value < 256
          call add(self.out, value)
        elseif value == 256   " end of block
          break
        else
          let [len, extra] = self.len_extra_bits[value]
          let len += self.stream.readint(extra)
          let dist_value = self.read_code(dist_code)
          let [dist, extra] = self.dist_extra_bits[dist_value]
          let dist += self.stream.readint(extra)
          let idx = len(self.out) - dist
          for i in range(len)
            call add(self.out, self.out[idx])
            let idx += 1
          endfor
        endif
      endwhile
    endif
    if bfinal
      break
    endif
  endwhile
  return self.out
endfunction

function s:Inflate.read_code(table)
  let code = ""
  while !has_key(a:table, code)
    let code .= self.stream.readbit()
  endwhile
  return a:table[code]
endfunction

function s:Inflate.read_custom_code()
  let idxorder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

  let hlit = self.stream.readint(5)
  let hdist = self.stream.readint(5)
  let hclen = self.stream.readint(4)

  let code_data = []
  for i in range(hclen + 4)
    call add(code_data, [idxorder[i], self.stream.readint(3)])
  endfor
  for i in range(hclen + 4, 18)
    call add(code_data, [idxorder[i], 0])
  endfor
  let hc_code = self.create_custom_table(code_data)

  let lengths = []
  while len(lengths) < hlit + 257 + hdist + 1
    let value = self.read_code(hc_code)
    if value <= 15
      call add(lengths, value)
    elseif value == 16
      let len = 3 + self.stream.readint(2)
      call extend(lengths, repeat([lengths[-1]], len))
    elseif value == 17
      let len = 3 + self.stream.readint(3)
      call extend(lengths, repeat([0], len))
    elseif value == 18
      let len = 11 + self.stream.readint(7)
      call extend(lengths, repeat([0], len))
    endif
  endwhile
  let code_data = map(range(hlit + 257), '[v:val, lengths[v:val]]')
  let lit_code = self.create_custom_table(code_data)
  let code_data = map(range(hdist + 1), '[v:val, lengths[hlit + 257 + v:val]]')
  let dist_code = self.create_custom_table(code_data)

  return [lit_code, dist_code]
endfunction

" @params code_data [[value, len], ...]
function s:Inflate.create_custom_table(code_data)
  let table = {}
  let prevlen = 0
  let ncode = 0
  for [value, len] in sort(copy(a:code_data), 's:sort_code_data')
    if len == 0
      continue
    endif
    if len != prevlen
      for i in range(prevlen, len - 1)
        let ncode = ncode * 2
      endfor
    endif
    let code = s:bin(ncode, len)
    let table[code] = value
    let ncode += 1
    let prevlen = len
  endfor
  return table
endfunction

" order by len ASC, value ASC
function s:sort_code_data(a, b)
  if a:a[1] == a:b[1]
    return a:a[0] == a:b[0] ? 0 : a:a[0] > a:b[0] ? 1 : -1
  endif
  return a:a[1] > a:b[1] ? 1 : -1
endfunction

function s:bin(ncode, len)
  let bits = ""
  for i in range(a:len)
    let bits = (bitwise#rshift(a:ncode, i) % 2) . bits
  endfor
  return bits
endfunction

let s:Inflate.fixed_lit_code = s:Inflate.create_custom_table(
      \ map(range(0, 143), '[v:val, 8]') +
      \ map(range(144, 255), '[v:val, 9]') +
      \ map(range(256, 279), '[v:val, 7]') +
      \ map(range(280, 287), '[v:val, 8]'))

let s:Inflate.fixed_dist_code = s:Inflate.create_custom_table(
      \ map(range(0, 29), '[v:val, 5]'))


" byteindex |       0|       1|...
" bitnumber |76543210|76543210|...
"  bitindex |76543210|FEDCBA98|...
let s:Bitstream = {}

function s:Bitstream.new(data)
  let obj = deepcopy(s:Bitstream)
  call obj.__init__(a:data)
  return obj
endfunction

function s:Bitstream.__init__(data)
  let self.data = a:data
  let self.bitindex = 0
endfunction

function s:Bitstream.skip_to_byte_align()
  if self.bitindex % 8 != 0
    let self.bitindex += 8 - (self.bitindex % 8)
  endif
endfunction

function s:Bitstream.readbit()
  let byteidx = self.bitindex / 8
  let bitnumber = self.bitindex % 8
  let bit = bitwise#rshift(self.data[byteidx], bitnumber) % 2
  let self.bitindex += 1
  return bit
endfunction

function s:Bitstream.readint(bitsize)
  let int = 0
  for i in range(a:bitsize)
    let int = bitwise#lshift(self.readbit(), i) + int
  endfor
  return int
endfunction

function s:Bitstream.readbytes(bytesize)
  call self.skip_to_byte_align()
  let byteindex = self.bitindex / 8
  let bytes = self.data[ byteindex : byteindex + a:bytesize - 1 ]
  let self.bitindex += a:bytesize * 8
  return bytes
endfunction


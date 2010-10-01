" [GZIP file format specification version 4.3]
" http://www.ietf.org/rfc/rfc1952.txt
" Last Change:  2010-10-02
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
" License:      This file is placed in the public domain.

function gunzip#gunzip(data)
  return s:gunzip(a:data)
endfunction

let s:ID1 = 0x1f
let s:ID2 = 0x8b

let s:CM_DEFLATE = 0x08

let s:FTEXT = 0x01
let s:FHCRC = 0x02
let s:FEXTRA = 0x04
let s:FNAME = 0x08
let s:FCOMMENT = 0x10

" @param Bytes data
function s:gunzip(data)
  if a:data[0] != s:ID1 || a:data[1] != s:ID2
    throw "invalid id"
  endif

  let start = 10

  if bitwise#and(a:data[3], s:FEXTRA)
    let xlen = a:data[start] + a:data[start + 1] * 0x100
    let xfield = a:data[start + 2 : start + 2 + len - 1]
    let start = start + 2 + xlen
  endif

  if bitwise#and(a:data[3], s:FNAME)
    let end = index(a:data, 0, start)
    let file_name = a:data[start : end - 1]
    let start = end + 1
  endif

  if bitwise#and(a:data[3], s:FCOMMENT)
    let end = index(a:data, 0, start)
    let comment = a:data[start : end - 1]
    let start = end + 1
  endif

  if bitwise#and(a:data[3], s:FHCRC)
    let crc16 = a:data[start : start + 1]
    let start = start + 2
  endif

  let crc32 = a:data[-8 : -5]
  let isize = a:data[-4 : ]
  let end = len(a:data) - 1 - 8

  let compressed_blocks = a:data[start : end]

  return inflate#inflate(compressed_blocks)
endfunction


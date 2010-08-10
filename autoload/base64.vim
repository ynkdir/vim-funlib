" base64 codec
" [The Base16, Base32, and Base64 Data Encodings]
" http://www.ietf.org/rfc/rfc3548.txt
" Last Change:  2010-08-03
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
" License:      This file is placed in the public domain.

let s:save_cpo = &cpo
set cpo&vim

function! base64#b64encode(data)
  let bytes = (type(a:data) == type("")) ? bytes#str2bytes(a:data) : a:data
  let b64 = s:b64encode(bytes, s:standard_table, '=')
  return join(b64, '')
endfunction

function! base64#b64decode(data)
  return bytes#bytes2str(base64#b64decode_bytes(a:data))
endfunction

function! base64#b64decode_bytes(data)
  let b64 = split(a:data, '\zs')
  let bytes = s:b64decode(b64, s:standard_table, '=')
  return bytes
endfunction

let s:standard_table = [
      \ "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P",
      \ "Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f",
      \ "g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v",
      \ "w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/"]

let s:urlsafe_table = [
      \ "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P",
      \ "Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f",
      \ "g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v",
      \ "w","x","y","z","0","1","2","3","4","5","6","7","8","9","-","_"]

function! s:b64encode(bytes, table, pad)
  let b64 = []
  for i in range(0, len(a:bytes) - 1, 3)
    let n = a:bytes[i] * 0x10000
          \ + get(a:bytes, i + 1, 0) * 0x100
          \ + get(a:bytes, i + 2, 0)
    call add(b64, a:table[n / 0x40000])
    call add(b64, a:table[n / 0x1000 % 0x40])
    call add(b64, a:table[n / 0x40 % 0x40])
    call add(b64, a:table[n % 0x40])
  endfor
  if len(a:bytes) % 3 == 2
    let b64[-1] = a:pad
  elseif len(a:bytes) % 3 == 1
    let b64[-1] = a:pad
    let b64[-2] = a:pad
  endif
  return b64
endfunction

function! s:b64decode(b64, table, pad)
  if len(a:b64) % 4 != 0
    throw "TypeError: Incorrect padding"
  endif
  if len(a:b64) == 0
    return []
  endif
  let a2i = {}
  for i in range(len(a:table))
    let a2i[a:table[i]] = i
  endfor
  let bytes = []
  for i in range(0, len(a:b64) - 1, 4)
    let n = a2i[a:b64[i]] * 0x40000
          \ + a2i[a:b64[i + 1]] * 0x1000
          \ + (a:b64[i + 2] == a:pad ? 0 : a2i[a:b64[i + 2]]) * 0x40
          \ + (a:b64[i + 3] == a:pad ? 0 : a2i[a:b64[i + 3]])
    call add(bytes, n / 0x10000)
    call add(bytes, n / 0x100 % 0x100)
    call add(bytes, n % 0x100)
  endfor
  if a:b64[-1] == a:pad
    unlet bytes[-1]
  elseif a:b64[-2] == a:pad
    unlet bytes[-1]
    unlet bytes[-1]
  endif
  return bytes
endfunction

let &cpo = s:save_cpo
unlet s:save_cpo

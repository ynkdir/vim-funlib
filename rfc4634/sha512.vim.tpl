" sha512 digest calculator    vim:set fdm=marker:
" This is a port of rfc4634 sha512 function.
" [US Secure Hash Algorithms (SHA and HMAC-SHA)]
" http://www.ietf.org/rfc/rfc4634.txt
" Last Change:  2010-08-05
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>

let s:save_cpo = &cpo
set cpo&vim

function! hashlib#sha512#new(...)
  let data = get(a:000, 0, [])
  return s:sha512.new(data)
endfunction

let s:sha512 = {}

function s:sha512.new(...)
  let data = get(a:000, 0, [])
  let obj = deepcopy(self)
  let obj.context = deepcopy(s:SHA512Context)
  let err = s:SHA512Reset(obj.context)
  if err
    throw printf("SHA512Reset Error %d", err)
  endif
  call obj.update(data)
  return obj
endfunction

function s:sha512.update(data)
  let data = (type(a:data) == type("") ? bytes#str2bytes(a:data) : a:data)
  let err = s:SHA512Input(self.context, data, len(data))
  if err
    throw printf("SHA512Input Error %d", err)
  endif
  return self
endfunction

function s:sha512.digest()
  let digest = repeat([0], s:SHA512HashSize)
  let err = s:SHA512Result(self.context, digest)
  if err
    throw printf("SHA512Result Error %d", err)
  endif
  return digest
endfunction

function s:sha512.hexdigest()
  return bytes#bytes2hex(self.digest())
endfunction

function s:sha512.copy()
  return deepcopy(self)
endfunction

function s:sha512.finalbits(bits, bitcount)
  let err = s:SHA512FinalBits(self.context, a:bits, a:bitcount)
  if err
    throw printf("SHA512FinalBits Error %d", err)
  endif
endfunction

" sha.h.vim {{{
#include "sha.h.vim"
" }}}
" sha-private.h.vim {{{
#include "sha-private.h.vim"
" }}}
" sha384-512.c.vim {{{
#include "sha384-512.c.vim"
" }}}

let &cpo = s:save_cpo
unlet s:save_cpo

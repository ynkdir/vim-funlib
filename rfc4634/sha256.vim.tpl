" sha256 digest calculator    vim:set fdm=marker:
" This is a port of rfc4634 sha256 function.
" [US Secure Hash Algorithms (SHA and HMAC-SHA)]
" http://www.ietf.org/rfc/rfc4634.txt
" Last Change:  2010-08-05
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>

let s:save_cpo = &cpo
set cpo&vim

function! hashlib#sha256#new(...)
  let data = get(a:000, 0, [])
  return s:sha256.new(data)
endfunction

let s:sha256 = {}

function s:sha256.new(...)
  let data = get(a:000, 0, [])
  let obj = deepcopy(self)
  let obj.context = deepcopy(s:SHA256Context)
  let err = s:SHA256Reset(obj.context)
  if err
    throw printf("SHA256Reset Error %d", err)
  endif
  call obj.update(data)
  return obj
endfunction

function s:sha256.update(data)
  let data = (type(a:data) == type("") ? bytes#str2bytes(a:data) : a:data)
  let err = s:SHA256Input(self.context, data, len(data))
  if err
    throw printf("SHA256Input Error %d", err)
  endif
  return self
endfunction

function s:sha256.digest()
  let digest = repeat([0], s:SHA256HashSize)
  let err = s:SHA256Result(self.context, digest)
  if err
    throw printf("SHA256Result Error %d", err)
  endif
  return digest
endfunction

function s:sha256.hexdigest()
  return bytes#bytes2hex(self.digest())
endfunction

function s:sha256.copy()
  return deepcopy(self)
endfunction

function s:sha256.finalbits(bits, bitcount)
  let err = s:SHA256FinalBits(self.context, a:bits, a:bitcount)
  if err
    throw printf("SHA256FinalBits Error %d", err)
  endif
endfunction

" sha.h.vim {{{
#include "sha.h.vim"
" }}}
" sha-private.h.vim {{{
#include "sha-private.h.vim"
" }}}
" sha224-256.c.vim {{{
#include "sha224-256.c.vim"
" }}}

let &cpo = s:save_cpo
unlet s:save_cpo

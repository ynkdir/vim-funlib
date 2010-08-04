" sha224 digest calculator    vim:set fdm=marker:
" This is a port of rfc4634 sha224 function.
" [US Secure Hash Algorithms (SHA and HMAC-SHA)]
" http://www.ietf.org/rfc/rfc4634.txt
" Last Change:  2010-08-05
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>

let s:save_cpo = &cpo
set cpo&vim

function! hashlib#sha224#new(...)
  let data = get(a:000, 0, [])
  return s:sha224.new(data)
endfunction

let s:sha224 = {}

function s:sha224.new(...)
  let data = get(a:000, 0, [])
  let obj = deepcopy(self)
  let obj.context = deepcopy(s:SHA224Context)
  let err = s:SHA224Reset(obj.context)
  if err
    throw printf("SHA224Reset Error %d", err)
  endif
  call obj.update(data)
  return obj
endfunction

function s:sha224.update(data)
  let data = (type(a:data) == type("") ? bytes#str2bytes(a:data) : a:data)
  let err = s:SHA224Input(self.context, data, len(data))
  if err
    throw printf("SHA224Input Error %d", err)
  endif
  return self
endfunction

function s:sha224.digest()
  let digest = repeat([0], s:SHA224HashSize)
  let err = s:SHA224Result(self.context, digest)
  if err
    throw printf("SHA224Result Error %d", err)
  endif
  return digest
endfunction

function s:sha224.hexdigest()
  return bytes#bytes2hex(self.digest())
endfunction

function s:sha224.copy()
  return deepcopy(self)
endfunction

function s:sha224.finalbits(bits, bitcount)
  let err = s:SHA224FinalBits(self.context, a:bits, a:bitcount)
  if err
    throw printf("SHA224FinalBits Error %d", err)
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

" sha384 digest calculator    vim:set fdm=marker:
" This is a port of rfc4634 sha384 function.
" [US Secure Hash Algorithms (SHA and HMAC-SHA)]
" http://www.ietf.org/rfc/rfc4634.txt
" Last Change:  2010-08-05
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>

let s:save_cpo = &cpo
set cpo&vim

function! hashlib#sha384#new(...)
  let data = get(a:000, 0, [])
  return s:sha384.new(data)
endfunction

let s:sha384 = {}

function s:sha384.new(...)
  let data = get(a:000, 0, [])
  let obj = deepcopy(self)
  let obj.context = deepcopy(s:SHA384Context)
  let err = s:SHA384Reset(obj.context)
  if err
    throw printf("SHA384Reset Error %d", err)
  endif
  call obj.update(data)
  return obj
endfunction

function s:sha384.update(data)
  let data = (type(a:data) == type("") ? bytes#str2bytes(a:data) : a:data)
  let err = s:SHA384Input(self.context, data, len(data))
  if err
    throw printf("SHA384Input Error %d", err)
  endif
  return self
endfunction

function s:sha384.digest()
  let digest = repeat([0], s:SHA384HashSize)
  let err = s:SHA384Result(self.context, digest)
  if err
    throw printf("SHA384Result Error %d", err)
  endif
  return digest
endfunction

function s:sha384.hexdigest()
  return bytes#bytes2hex(self.digest())
endfunction

function s:sha384.copy()
  return deepcopy(self)
endfunction

function s:sha384.finalbits(bits, bitcount)
  let err = s:SHA384FinalBits(self.context, a:bits, a:bitcount)
  if err
    throw printf("SHA384FinalBits Error %d", err)
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

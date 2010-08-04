" sha1 digest calculator    vim:set fdm=marker:
" This is a port of rfc4634 sha1 function.
" [US Secure Hash Algorithms (SHA and HMAC-SHA)]
" http://www.ietf.org/rfc/rfc4634.txt
" Last Change:  2010-08-05
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>

let s:save_cpo = &cpo
set cpo&vim

function! hashlib#sha1#new(...)
  let data = get(a:000, 0, [])
  return s:sha1.new(data)
endfunction

let s:sha1 = {}

function s:sha1.new(...)
  let data = get(a:000, 0, [])
  let obj = deepcopy(self)
  let obj.context = deepcopy(s:SHA1Context)
  let err = s:SHA1Reset(obj.context)
  if err
    throw printf("SHA1Reset Error %d", err)
  endif
  call obj.update(data)
  return obj
endfunction

function s:sha1.update(data)
  let data = (type(a:data) == type("") ? bytes#str2bytes(a:data) : a:data)
  let err = s:SHA1Input(self.context, data, len(data))
  if err
    throw printf("SHA1Input Error %d", err)
  endif
  return self
endfunction

function s:sha1.digest()
  let digest = repeat([0], s:SHA1HashSize)
  let err = s:SHA1Result(self.context, digest)
  if err
    throw printf("SHA1Result Error %d", err)
  endif
  return digest
endfunction

function s:sha1.hexdigest()
  return bytes#bytes2hex(self.digest())
endfunction

function s:sha1.copy()
  return deepcopy(self)
endfunction

function s:sha1.finalbits(bits, bitcount)
  let err = s:SHA1FinalBits(self.context, a:bits, a:bitcount)
  if err
    throw printf("SHA1FinalBits Error %d", err)
  endif
endfunction

" sha.h.vim {{{
#include "sha.h.vim"
" }}}
" sha-private.h.vim {{{
#include "sha-private.h.vim"
" }}}
" sha1.c.vim {{{
#include "sha1.c.vim"
" }}}

let &cpo = s:save_cpo
unlet s:save_cpo

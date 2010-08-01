" md5 digest calculator     vim:set fdm=marker:
" This is a port of rfc1321 md5 function.
" [The MD5 Message-Digest Algorithm]
" http://www.ietf.org/rfc/rfc1321.txt
" Last Change:  2010-08-01
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
"
" Original License:
" Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
" rights reserved.
"
" License to copy and use this software is granted provided that it
" is identified as the "RSA Data Security, Inc. MD5 Message-Digest
" Algorithm" in all material mentioning or referencing this software
" or this function.
"
" License is also granted to make and use derivative works provided
" that such works are identified as "derived from the RSA Data
" Security, Inc. MD5 Message-Digest Algorithm" in all material
" mentioning or referencing the derived work.
"
" RSA Data Security, Inc. makes no representations concerning either
" the merchantability of this software or the suitability of this
" software for any particular purpose. It is provided "as is"
" without express or implied warranty of any kind.
"
" These notices must be retained in any copies of any part of this
" documentation and/or software.

let s:save_cpo = &cpo
set cpo&vim

function! hashlib#md5#new(...)
  let data = get(a:000, 0, [])
  return s:md5.new(data)
endfunction

let s:md5 = {}

function s:md5.new(...)
  let data = get(a:000, 0, [])
  let obj = deepcopy(self)
  let obj.context = deepcopy(s:MD5_CTX)
  call s:MD5Init(obj.context)
  call obj.update(data)
  return obj
endfunction

function s:md5.update(data)
  let data = (type(a:data) == type("")) ? bytes#str2bytes(a:data) : a:data
  call s:MD5Update(self.context, data, len(data))
  return self
endfunction

function s:md5.digest()
  let digest = repeat([0], 16)
  call s:MD5Final(digest, self.context)
  return digest
endfunction

function s:md5.hexdigest()
  return bytes#bytes2hex(self.digest())
endfunction

function s:md5.copy()
  return deepcopy(self)
endfunction

" md5.h.vim {{{
#include "md5.h.vim"
" }}}
" md5c.c.vim {{{
#include "md5c.c.vim"
" }}}

let &cpo = s:save_cpo
unlet s:save_cpo

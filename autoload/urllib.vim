" [Uniform Resource Identifier (URI): Generic Syntax]
" http://www.ietf.org/rfc/rfc3986.txt
" Last Change:  2010-08-10
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
" License:      This file is placed in the public domain.

let s:save_cpo = &cpo
set cpo&vim

let s:unreserved_rfc2396 = '[A-Za-z0-9\-._~!*''()]'
let s:unreserved_rfc3986 = '[A-Za-z0-9\-._~]'


" @param String component
" @param String safe (default:'/')
" @return String
function! urllib#quote(component, ...)
  let safe = get(a:000, 0, '/')
  let unreserved = s:unreserved_rfc3986
  let buf = []
  for c in split(a:component, '\zs')
    if c =~ unreserved || stridx(safe, c) != -1
      call add(buf, c)
    else
      call add(buf, urllib#percent_encode(c))
    endif
  endfor
  return join(buf, '')
endfunction


function! urllib#percent_encode(s)
  return join(map(bytes#str2bytes(a:s), 'printf("%%%02X", v:val)'), '')
endfunction


" @param mixed query Dictionary/List([[key1,val1],[key2,val2], ...])
" @param String safe (default:'')
" @return String
function! urllib#urlencode(query, ...)
  let safe = get(a:000, 0, '')
  if type(a:query) != type({}) && type(a:query) != type([])
    throw "TypeError"
  endif
  if type(a:query) == type({})
    let query = items(a:query)
  else
    let query = a:query
  endif
  let buf = []
  for [key, val] in query
    let param = urllib#quote(key, safe) . '=' . urllib#quote(val, safe)
    call add(buf, param)
  endfor
  return join(buf, '&')
endfunction

let &cpo = s:save_cpo
unlet s:save_cpo

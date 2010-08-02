" This is a port of rfc2104 hmac function.
" [HMAC: Keyed-Hashing for Message Authentication]
" http://www.ietf.org/rfc/rfc2104.txt
" Last Change:  2010-08-02
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
" License:      This file is placed in the public domain.

function hmac#md5(key, text)
  return hmac#new(a:key, a:text, function('hashlib#md5#new')).hexdigest()
endfunction

function hmac#sha1(key, text)
  return hmac#new(a:key, a:text, function('hashlib#sha1#new')).hexdigest()
endfunction

function hmac#sha224(key, text)
  return hmac#new(a:key, a:text, function('hashlib#sha224#new')).hexdigest()
endfunction

function hmac#sha256(key, text)
  return hmac#new(a:key, a:text, function('hashlib#sha256#new')).hexdigest()
endfunction

function hmac#sha384(key, text)
  return hmac#new(a:key, a:text, function('hashlib#sha384#new'), 128).hexdigest()
endfunction

function hmac#sha512(key, text)
  return hmac#new(a:key, a:text, function('hashlib#sha512#new'), 128).hexdigest()
endfunction

function hmac#new(...)
  return call(s:hmac.new, a:000, s:hmac)
endfunction

let s:hmac = {}

function s:hmac.new(key, ...)
  let key = (type(a:key) == type("")) ? bytes#str2bytes(a:key) : a:key
  let msg = get(a:000, 0, [])
  let Digestmod = get(a:000, 1, function('hashlib#md5#new'))
  let blocksize = get(a:000, 2, 64) " 512-bit HMAC
  let obj = deepcopy(self)
  let obj.digestmod = Digestmod
  if len(key) > blocksize
    let key = Digestmod(key).digest()
  endif
  let k_ipad = repeat([0], blocksize)
  let k_opad = repeat([0], blocksize)
  for i in range(blocksize)
    let k_ipad[i] = bitwise#xor(get(key, i, 0), 0x36)
    let k_opad[i] = bitwise#xor(get(key, i, 0), 0x5c)
  endfor
  let obj.inner = Digestmod(k_ipad).update(msg)
  let obj.outer = Digestmod(k_opad)
  return obj
endfunction

function s:hmac.update(msg)
  call self.inner.update(a:msg)
endfunction

function s:hmac.digest()
  let outer = self.outer.copy()
  return outer.update(self.inner.digest()).digest()
endfunction

function s:hmac.hexdigest()
  return bytes#bytes2hex(self.digest())
endfunction

function s:hmac.copy()
  return deepcopy(self)
endfunction


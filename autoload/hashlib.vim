function! hashlib#md5(data)
  return hashlib#md5#new(a:data).hexdigest()
endfunction

function! hashlib#sha1(data)
  return hashlib#sha1#new(a:data).hexdigest()
endfunction

function! hashlib#sha224(data)
  return hashlib#sha224#new(a:data).hexdigest()
endfunction

function! hashlib#sha256(data)
  return hashlib#sha256#new(a:data).hexdigest()
endfunction

function! hashlib#sha384(data)
  return hashlib#sha384#new(a:data).hexdigest()
endfunction

function! hashlib#sha512(data)
  return hashlib#sha512#new(a:data).hexdigest()
endfunction

function! bytes#str2bytes(str)
  return map(range(len(a:str)), 'char2nr(a:str[v:val])')
endfunction

function! bytes#bytes2str(bytes)
  return eval('"' . join(map(copy(a:bytes), 'printf(''\x%02x'', v:val)'), '') . '"')
endfunction

function! bytes#bytes2hex(bytes)
  return join(map(copy(a:bytes), 'printf("%02x", v:val)'), '')
endfunction

function! bytes#hex2bytes(hex)
  return map(split(a:hex, '..\zs'), 'str2nr(v:val, 16)')
endfunction

function! bytes#readfile(filename)
  let bytes = []
  let s = system('xxd -p ' . fnameescape(a:filename))
  if v:shell_error
    throw "Can't read file " . a:filename
  endif
  call substitute(s, '\x\x', '\=empty(add(bytes, str2nr(submatch(0), 16)))', 'g')
  return bytes
endfunction

function! bytes#writefile(filename, bytes)
  let bytes = (type(a:bytes) == type("") ? bytes#str2bytes(a:bytes) : a:bytes)
  let hex = bytes#bytes2hex(bytes)
  call system('xxd -p -r - ' . fnameescape(a:filename), hex)
  if v:shell_error
    throw "Can't write file " . a:filename
  endif
endfunction

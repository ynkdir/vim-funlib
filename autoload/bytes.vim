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

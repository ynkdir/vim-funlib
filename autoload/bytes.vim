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

" XXX: Is this safe in multibyte environment?
function! bytes#readfile(filename)
  try
    let lines = readfile(a:filename, 'b')
  catch /^Vim\%((\a\+)\)\=:E484:/
    throw "Can't read file"
  endtry
  let data = []
  for line in lines
    if !empty(data)
      call add(data, 10)
    endif
    call extend(data, map(range(len(line)), 'line[v:val] == "\n" ? 0 : char2nr(line[v:val])'))
  endfor
  return data
endfunction

function! bytes#writefile(filename, data)
  let table = map(range(256), 'printf(''\x%02x'', v:val == 0 ? 10 : v:val)')
  let lines = []
  let start = 0
  while start < len(a:data)
    let end = index(a:data, 10, start)
    if end == -1
      let end = len(a:data)
    endif
    let line = eval('"' . join(map(range(start, end - 1), 'table[a:data[v:val]]'), '') . '"')
    call add(lines, line)
    if end == len(a:data) - 1
      call add(lines, '')
    endif
    let start = end + 1
  endwhile
  if writefile(lines, a:filename, 'b') != 0
    throw "Can't write file"
  endif
endfunction

function! bytes#readfilexxd(filename)
  let bytes = []
  let s = system('xxd -p ' . fnameescape(a:filename))
  if v:shell_error
    throw "Can't read file " . a:filename
  endif
  call substitute(s, '\x\x', '\=empty(add(bytes, str2nr(submatch(0), 16)))', 'g')
  return bytes
endfunction

function! bytes#writefilexxd(filename, bytes)
  let bytes = (type(a:bytes) == type("") ? bytes#str2bytes(a:bytes) : a:bytes)
  let hex = bytes#bytes2hex(bytes)
  call system('xxd -p -r - ' . fnameescape(a:filename), hex)
  if v:shell_error
    throw "Can't write file " . a:filename
  endif
endfunction

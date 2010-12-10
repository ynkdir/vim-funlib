function! bytes#tobytes(v)
  if type(a:v) == type([])
    return a:v
  elseif type(a:v) == type("")
    return bytes#str2bytes(a:v)
  else
    throw "Can't convert to bytes"
  endif
endfunction

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

function! bytes#lines2bytes(lines)
  let bytes = []
  let first = 1
  for line in a:lines
    if !first
      call add(bytes, 10)
    endif
    let first = 0
    call extend(bytes, map(range(len(line)), 'line[v:val] == "\n" ? 0 : char2nr(line[v:val])'))
  endfor
  return bytes
endfunction

function! bytes#bytes2lines(bytes)
  let table = map(range(256), 'printf(''\x%02x'', v:val == 0 ? 10 : v:val)')
  let lines = []
  let start = 0
  while start < len(a:bytes)
    let end = index(a:bytes, 10, start)
    if end == -1
      let end = len(a:bytes)
    endif
    let line = eval('"' . join(map(range(start, end - 1), 'table[a:bytes[v:val]]'), '') . '"')
    call add(lines, line)
    if end == len(a:bytes) - 1
      call add(lines, '')
    endif
    let start = end + 1
  endwhile
  return lines
endfunction

" XXX: Is this safe in multibyte environment?
function! bytes#readfile(filename)
  try
    let lines = readfile(a:filename, 'b')
  catch /^Vim\%((\a\+)\)\=:E484:/
    throw "Can't read file"
  endtry
  let bytes = bytes#lines2bytes(lines)
  return bytes
endfunction

function! bytes#writefile(bytes, filename)
  let lines = bytes#bytes2lines(a:bytes)
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

function! bytes#writefilexxd(bytes, filename)
  let bytes = (type(a:bytes) == type("") ? bytes#str2bytes(a:bytes) : a:bytes)
  let hex = bytes#bytes2hex(bytes)
  call system('xxd -p -r - ' . fnameescape(a:filename), hex)
  if v:shell_error
    throw "Can't write file " . a:filename
  endif
endfunction

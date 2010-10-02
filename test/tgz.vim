source <sfile>:p:h/test.vim
INFO tgz test
let g:_tgzfile = expand("<sfile>:p:h") . "/tgztest.tgz"
function! _getfile(tgzfile, path)
  let data = bytes#readfile(a:tgzfile)
  let data = gunzip#gunzip(data)
  for entry in untar#untar(data)
    if entry.name == a:path
      return bytes#bytes2str(entry.content)
    endif
  endfor
  throw "file not found"
endfunction
OK _getfile(g:_tgzfile, 'tgztest/hello-world.txt') == "Hello, world!\n"
OK _getfile(g:_tgzfile, 'tgztest/sample.txt') == "The quick brown fox jumps over the lazy dog\n"

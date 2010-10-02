source <sfile>:p:h/test.vim
INFO zip test
let g:_zipfile = expand("<sfile>:p:h") . "/ziptest.zip"
function! _getfile(zipfile, path)
  let data = bytes#readfile(a:zipfile)
  for entry in unzip#unzip(data)
    if entry.filename == a:path
      return bytes#bytes2str(entry.content)
    endif
  endfor
  throw "file not found"
endfunction
OK _getfile(g:_zipfile, 'ziptest/hello-world.txt') == "Hello, world!\n"
OK _getfile(g:_zipfile, 'ziptest/sample.txt') == repeat("The quick brown fox jumps over the lazy dog\n", 5)

if !exists('s:init')
  let s:init = 1
  let &runtimepath = &runtimepath . ',' . expand('<sfile>:p:h:h')
  set cpo-=C
  syntax on
  set nomore
  let g:TESTEASY = 1
endif

redir! > test.out
source <sfile>:p:h/base64.vim
source <sfile>:p:h/hmac.vim
source <sfile>:p:h/md5.vim
source <sfile>:p:h/sha1.vim
source <sfile>:p:h/shatest.vim
source <sfile>:p:h/urllib.vim
source <sfile>:p:h/mt19937ar.vim
source <sfile>:p:h/tgz.vim
source <sfile>:p:h/zip.vim
source <sfile>:p:h/bitwise.vim
redir END

quit

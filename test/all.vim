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
redir END

quit

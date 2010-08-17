source <sfile>:p:h/test.vim
let g:_mt19937ar_expect = readfile(expand("<sfile>:p:h:h") . "/mt19937ar/mt19937ar.out")
INFO mt1937ar test
OK split(random#mt19937ar#_main(), '\n') ==# g:_mt19937ar_expect

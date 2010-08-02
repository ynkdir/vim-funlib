command! -nargs=* INFO call s:info(<q-args>)
command! -nargs=* OK call s:ok(<q-args>)

function! s:info(expr)
  echohl Visual
  echomsg a:expr . repeat(" ", &columns - len(a:expr) - 1)
  echohl None
endfunction

function! s:ok(expr)
  if eval(a:expr)
    echomsg "  PASS:" a:expr
  else
    echohl Error
    echomsg "FAILED:" a:expr
    echohl None
  endif
  echomsg
endfunction


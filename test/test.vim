command! -nargs=* INFO call s:info(<q-args>)
command! -nargs=* OK call s:ok(<q-args>)
command! -nargs=* EXCEPT call s:except(<q-args>)

function! s:info(expr)
  echohl Visual
  echomsg a:expr . repeat(" ", &columns - len(a:expr) - 1)
  echohl None
endfunction

function! s:ok(expr)
  if eval(a:expr)
    echomsg "  PASS: OK" a:expr
  else
    echohl Error
    echomsg "FAILED: OK" a:expr
    echohl None
  endif
  echomsg
endfunction

function! s:except(expr)
  let _ = matchlist(a:expr, '^\(.*\)\s\+=>\s\+\(.*\)$')
  let expr = _[1]
  let exception = eval(_[2])
  try
    call eval(expr)
    echohl Error
    echomsg "FAILED: EXCEPT" a:expr
    echohl None
  catch
    if v:exception =~ exception
      echomsg "  PASS: EXCEPT" a:expr
    else
      echohl Error
      echomsg "FAILED: EXCEPT" a:expr
      echohl None
    endif
  endtry
endfunction


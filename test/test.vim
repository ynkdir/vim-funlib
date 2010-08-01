command! -nargs=* OK
      \   if eval(<q-args>)
      \ |   echo "  PASS:" <q-args>
      \ | else
      \ |   echohl Error
      \ |   echo "FAILED:" <q-args>
      \ |   echohl None
      \ | endif

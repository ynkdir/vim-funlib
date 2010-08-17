
function random#srand(seed)
  call random#mt19937ar#srand(a:seed)
endfunction

function random#rand()
  return random#mt19937ar#rand()
endfunction


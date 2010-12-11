
" @param x Number (default=current time)
function random#seed(...)
  let x = get(a:000, 0, float2nr(fmod(str2float(reltimestr(reltime())) * 256, 2147483648.0)))
  call random#mt19937ar#seed(x)
endfunction

" @return Float [0.0, 1.0)
function random#random()
  return random#mt19937ar#random()
endfunction

" Return a random integer N such that a <= N <= b.
function random#randint(a, b)
  return float2nr(a:a + ((a:b - a:a + 1) * random#random()))
endfunction

" Return a random element from the non-empty sequence seq.
function random#choice(seq)
  return a:seq[float2nr(random#random() * len(a:seq))]
endfunction

" Shuffle the sequence x in place
function random#shuffle(x)
  for i in reverse(range(1, len(a:x) - 1))
    let j = float2nr(random#random() * (i + 1))
    let [a:x[i], a:x[j]] = [a:x[j], a:x[i]]
  endfor
  return a:x
endfunction

" initialize
call random#seed()


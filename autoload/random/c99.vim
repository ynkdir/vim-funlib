" Example of the C99 draft 7.20.2 Pseudo random sequence generation functions
"
" EXAMPLE The following functions define a portable implementation of
" rand and srand.
"
" static unsigned long int next = 1;
"
" int rand(void) // RAND_MAX assumed to be 32767
" {
"     next = next * 1103515245 + 12345;
"     return (unsigned int)(next/65536) % 32768;
" }
"
" void srand(unsigned int seed)
" {
"     next = seed;
" }

function random#c99#seed(x)
  call s:srand(a:x)
endfunction

function random#c99#random()
  "return s:rand() / (s:RAND_MAX + 1.0)
  return s:genrand_res53()
endfunction

let s:RAND_MAX = 32767

let s:next = 1

function! s:rand()
  let s:next = s:next * 1103515245 + 12345
  return ((s:next < 0 ? s:next - 0x80000000 : s:next) / 65536) % 32768
endfunction

function! s:srand(seed)
  let s:next = a:seed
endfunction

" FIXME: quality?
function! s:genrand_res53()
  let a = (s:rand() / 0x08 * 0x8000) + s:rand() " 27 bit
  let b = (s:rand() / 0x10 * 0x8000) + s:rand() " 26 bit
  return (a*67108864.0+b)*(1.0/9007199254740992.0)
endfunction


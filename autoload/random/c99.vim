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
  return s:genrand_res53()
endfunction

let s:RAND_MAX = 32767

let s:next = 1

function! s:rand()
  let s:next = s:next * 1103515245 + 12345
  if s:next >= 0
    return (s:next / 65536) % 32768
  else
    " MSB can be ignored
    return ((s:next - 0x80000000) / 65536) % 32768
  endif
endfunction

function! s:srand(seed)
  let s:next = a:seed
endfunction

" FIXME: quality?
function! s:genrand_int32()
  let a = s:rand() / 0x800 * 0x10000000
  let b = s:rand() / 0x800 * 0x1000000
  let c = s:rand() / 0x800 * 0x100000
  let d = s:rand() / 0x800 * 0x10000
  let e = s:rand() / 0x800 * 0x1000
  let f = s:rand() / 0x800 * 0x100
  let g = s:rand() / 0x800 * 0x10
  let h = s:rand() / 0x800
  return a + b + c + d + e + f + g + h
endfunction

function! s:genrand_res53()
  let a = bitwise#uint32_to_float(bitwise#rshift(s:genrand_int32(), 5))
  let b = bitwise#uint32_to_float(bitwise#rshift(s:genrand_int32(), 6))
  return (a*67108864.0+b)*(1.0/9007199254740992.0)
endfunction


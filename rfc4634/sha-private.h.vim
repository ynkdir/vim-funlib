"*************************** sha-private.h ***************************
"********************** See RFC 4634 for details *********************
"
" These definitions are defined in FIPS-180-2, section 4.1.
" Ch() and Maj() are defined identically in sections 4.1.1,
" 4.1.2 and 4.1.3.
"
" The definitions used in FIPS-180-2 are as follows:
"

let s:USE_MODIFIED_MACROS = 1

"#ifndef USE_MODIFIED_MACROS
if !exists("s:USE_MODIFIED_MACROS")
  "#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))
  function! s:SHA_Ch(x, y, z)
    return bitwise#xor(bitwise#and(a:x, a:y), bitwise#and(bitwise#not(a:x), a:z))
  endfunction
  "#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
  function! s:SHA_Maj(x, y, z)
    return bitwise#xor(bitwise#xor(bitwise#and(a:x, a:y), bitwise#and(a:x, a:z)), bitwise#and(a:y, a:z))
  endfunction
else " USE_MODIFIED_MACROS
  "
  " The following definitions are equivalent and potentially faster.
  "
  "#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))
  function! s:SHA_Ch(x, y, z)
    return bitwise#xor(bitwise#and(a:x, bitwise#xor(a:y, a:z)), a:z)
  endfunction
  "#define SHA_Maj(x, y, z)     (((x) & ((y) | (z))) | ((y) & (z)))
  function! s:SHA_Maj(x, y, z)
    return bitwise#or(bitwise#and(a:x, bitwise#or(a:y, a:z)), bitwise#and(a:y, a:z))
  endfunction
endif " USE_MODIFIED_MACROS

"#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))
function! s:SHA_Parity(x, y, z)
  return bitwise#xor(bitwise#xor(a:x, a:y), a:z)
endfunction


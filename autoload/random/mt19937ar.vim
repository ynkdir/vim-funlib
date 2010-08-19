" Mersenne Twister
" http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
" http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/emt19937ar.html
" This is a port of mt19937ar.c
" Last Change:  2010-08-17
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
" Original Copyright:
"   A C-program for MT19937, with initialization improved 2002/1/26.
"   Coded by Takuji Nishimura and Makoto Matsumoto.
"
"   Before using, initialize the state by using init_genrand(seed)
"   or init_by_array(init_key, key_length).
"
"   Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
"   All rights reserved.
"
"   Redistribution and use in source and binary forms, with or without
"   modification, are permitted provided that the following conditions
"   are met:
"
"     1. Redistributions of source code must retain the above copyright
"        notice, this list of conditions and the following disclaimer.
"
"     2. Redistributions in binary form must reproduce the above copyright
"        notice, this list of conditions and the following disclaimer in the
"        documentation and/or other materials provided with the distribution.
"
"     3. The names of its contributors may not be used to endorse or promote
"        products derived from this software without specific prior written
"        permission.
"
"   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
"   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
"   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
"   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
"   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
"   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
"   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
"   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
"   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
"   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

function random#mt19937ar#seed(x)
  call s:init_by_array([a:x])
endfunction

function random#mt19937ar#random()
  return s:genrand_res53()
endfunction

" for test
function random#mt19937ar#_main()
  return s:main()
endfunction

let s:N = 624
let s:M = 397
let s:MATRIX_A = 0x9908b0df
let s:UPPER_MASK = 0x80000000
let s:LOWER_MASK = 0x7fffffff

let s:mt = repeat([0], s:N)
let s:mti = s:N + 1

function! s:init_genrand(s)
  let s:mt[0] = a:s
  let s:mti = 1
  while s:mti < s:N
    let s:mt[s:mti] = 1812433253 * bitwise#xor(s:mt[s:mti-1], bitwise#rshift(s:mt[s:mti-1], 30)) + s:mti
    let s:mti += 1
  endwhile
endfunction

function! s:init_by_array(init_key)
  let key_length = len(a:init_key)
  call s:init_genrand(19650218)
  let i = 1
  let j = 0
  let k = (s:N > key_length ? s:N : key_length)
  while k
    let s:mt[i] = bitwise#xor(s:mt[i], bitwise#xor(s:mt[i-1], bitwise#rshift(s:mt[i-1], 30)) * 1664525) + a:init_key[j] + j
    let i += 1
    let j += 1
    if i >= s:N
      let s:mt[0] = s:mt[s:N-1]
      let i = 1
    endif
    if j >= key_length
      let j = 0
    endif
    let k -= 1
  endwhile
  let k = s:N - 1
  while k
    let s:mt[i] = bitwise#xor(s:mt[i], bitwise#xor(s:mt[i-1], bitwise#rshift(s:mt[i-1], 30)) * 1566083941) - i
    let i += 1
    if i >= s:N
      let s:mt[0] = s:mt[s:N-1]
      let i = 1
    endif
    let k -= 1
  endwhile

  let s:mt[0] = 0x80000000
endfunction

function! s:genrand_int32()
  let mag01 = [0, s:MATRIX_A]

  if s:mti >= s:N
    if s:mti == s:N + 1
      call s:init_genrand(5489)
    endif

    let kk = 0
    while kk < s:N - s:M
      let y = bitwise#or(bitwise#and(s:mt[kk], s:UPPER_MASK), bitwise#and(s:mt[kk+1], s:LOWER_MASK))
      let s:mt[kk] = bitwise#xor(bitwise#xor(s:mt[kk+s:M], bitwise#rshift(y, 1)), mag01[y % 2])
      let kk += 1
    endwhile
    while kk < s:N - 1
      let y = bitwise#or(bitwise#and(s:mt[kk], s:UPPER_MASK), bitwise#and(s:mt[kk+1], s:LOWER_MASK))
      let s:mt[kk] = bitwise#xor(bitwise#xor(s:mt[kk+(s:M-s:N)], bitwise#rshift(y, 1)), mag01[y % 2])
      let kk += 1
    endwhile
    let y = bitwise#or(bitwise#and(s:mt[s:N-1], s:UPPER_MASK), bitwise#and(s:mt[0], s:LOWER_MASK))
    let s:mt[s:N-1] = bitwise#xor(bitwise#xor(s:mt[s:M-1], bitwise#rshift(y, 1)), mag01[y % 2])

    let s:mti = 0
  endif

  let y = s:mt[s:mti]
  let s:mti += 1

  let y = bitwise#xor(y, bitwise#rshift(y, 11))
  let y = bitwise#xor(y, bitwise#and(bitwise#lshift(y, 7), 0x9d2c5680))
  let y = bitwise#xor(y, bitwise#and(bitwise#lshift(y, 15), 0xefc60000))
  let y = bitwise#xor(y, bitwise#rshift(y, 18))

  return y
endfunction

function! s:genrand_int31()
  return bitwise#rshift(s:genrand_int32(), 1)
endfunction

function! s:genrand_real1()
  return bitwise#uint32_to_float(s:genrand_int32())*(1.0/4294967295.0)
endfunction

function! s:genrand_real2()
  return bitwise#uint32_to_float(s:genrand_int32())*(1.0/4294967296.0)
endfunction

function! s:genrand_real3()
  return (bitwise#uint32_to_float(s:genrand_int32()) + 0.5)*(1.0/4294967296.0)
endfunction

function! s:genrand_res53()
  let a = bitwise#uint32_to_float(bitwise#rshift(s:genrand_int32(), 5))
  let b = bitwise#uint32_to_float(bitwise#rshift(s:genrand_int32(), 6))
  return (a*67108864.0+b)*(1.0/9007199254740992.0)
endfunction

function! s:main()
  let init = [0x123, 0x234, 0x345, 0x456]
  call s:init_by_array(init)
  let buf = ""
  let buf .= "1000 outputs of genrand_int32()\n"
  for i in range(1000)
    let buf .= printf("%10u ", s:genrand_int32())
    if i % 5 == 4
      let buf .= "\n"
    endif
  endfor
  let buf .= "\n1000 outputs of genrand_real2()\n"
  for i in range(1000)
    let buf .= printf("%10.8f ", s:genrand_real2())
    if i % 5 == 4
      let buf .= "\n"
    endif
  endfor
  return buf
endfunction


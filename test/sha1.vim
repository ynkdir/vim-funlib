source <sfile>:p:h/test.vim
INFO sha1 test
function! _sha1test(input, repeat)
  let sha1 = hashlib#sha1#new()
  for i in range(a:repeat)
    call sha1.update(a:input)
  endfor
  return sha1.hexdigest()
endfunction
OK _sha1test("abc", 1) ==# "a9993e364706816aba3e25717850c26c9cd0d89d"
OK _sha1test("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1) ==# "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
if !exists('g:TESTEASY')
  try
    INFO Test 3 will take about 1 hour.  Press CTRL-C to skip.\n
    OK _sha1test("a", 1000000) ==# "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
  catch /^Vim:Interrupt$/
    INFO Skip ...
    " eat keys
    while getchar(0) | endwhile
  endtry
endif
OK _sha1test("0123456701234567012345670123456701234567012345670123456701234567", 10) ==# "dea356a2cddd90c7a7ecedc5ebb563934f460452"

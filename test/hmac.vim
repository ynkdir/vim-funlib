so <sfile>:p:h/test.vim
" [Test Cases for HMAC-MD5 and HMAC-SHA-1]
" http://www.ietf.org/rfc/rfc2202.txt
" Test Cases for HMAC-MD5
OK hmac#md5(repeat("\x0b", 16), "Hi There") ==# "9294727a3638bb1c13f48ef8158bfc9d"
OK hmac#md5("Jefe", "what do ya want for nothing?") ==# "750c783e6ab0b503eaa86e310a5db738"
OK hmac#md5(repeat("\xaa", 16), repeat("\xdd", 50)) ==# "56be34521d144c88dbb8c733f0e8b3f6"
OK hmac#md5(bytes#hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"), repeat([0xcd], 50)) ==# "697eaf0aca3a3aea3a75164746ffaa79"
OK hmac#md5(repeat("\x0c", 16), "Test With Truncation") ==# "56461ef2342edc00f9bab995690efd4c"
OK hmac#md5(repeat("\xaa", 80), "Test Using Larger Than Block-Size Key - Hash Key First") ==# "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
OK hmac#md5(repeat("\xaa", 80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",) ==# "6f630fad67cda0ee1fb1f562db3aa53e"
" Test Cases for HMAC-SHA1
OK hmac#sha1(repeat("\x0b", 20), "Hi There") ==# "b617318655057264e28bc0b6fb378c8ef146be00"
OK hmac#sha1("Jefe", "what do ya want for nothing?") ==# "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
OK hmac#sha1(repeat("\xaa", 20), repeat("\xdd", 50)) ==# "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
OK hmac#sha1(bytes#hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"), repeat([0xcd], 50)) ==# "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
OK hmac#sha1(repeat("\x0c", 20), "Test With Truncation") ==# "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
OK hmac#sha1(repeat("\xaa", 80), "Test Using Larger Than Block-Size Key - Hash Key First") ==# "aa4ae5e15272d00e95705637ce8a3b55ed402112"
OK hmac#sha1(repeat("\xaa", 80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data") ==# "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"

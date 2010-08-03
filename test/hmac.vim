source <sfile>:p:h/test.vim
INFO hmac test
INFO [Test Cases for HMAC-MD5 and HMAC-SHA-1]
INFO http://www.ietf.org/rfc/rfc2202.txt
INFO Test Cases for HMAC-MD5
OK hmac#md5(repeat("\x0b", 16), "Hi There") ==# "9294727a3638bb1c13f48ef8158bfc9d"
OK hmac#md5("Jefe", "what do ya want for nothing?") ==# "750c783e6ab0b503eaa86e310a5db738"
OK hmac#md5(repeat("\xaa", 16), repeat("\xdd", 50)) ==# "56be34521d144c88dbb8c733f0e8b3f6"
OK hmac#md5(bytes#hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"), repeat([0xcd], 50)) ==# "697eaf0aca3a3aea3a75164746ffaa79"
OK hmac#md5(repeat("\x0c", 16), "Test With Truncation") ==# "56461ef2342edc00f9bab995690efd4c"
OK hmac#md5(repeat("\xaa", 80), "Test Using Larger Than Block-Size Key - Hash Key First") ==# "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
OK hmac#md5(repeat("\xaa", 80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",) ==# "6f630fad67cda0ee1fb1f562db3aa53e"
INFO Test Cases for HMAC-SHA1
OK hmac#sha1(repeat("\x0b", 20), "Hi There") ==# "b617318655057264e28bc0b6fb378c8ef146be00"
OK hmac#sha1("Jefe", "what do ya want for nothing?") ==# "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
OK hmac#sha1(repeat("\xaa", 20), repeat("\xdd", 50)) ==# "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
OK hmac#sha1(bytes#hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"), repeat([0xcd], 50)) ==# "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
OK hmac#sha1(repeat("\x0c", 20), "Test With Truncation") ==# "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
OK hmac#sha1(repeat("\xaa", 80), "Test Using Larger Than Block-Size Key - Hash Key First") ==# "aa4ae5e15272d00e95705637ce8a3b55ed402112"
OK hmac#sha1(repeat("\xaa", 80), "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data") ==# "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
INFO [Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
INFO  HMAC-SHA-384, and HMAC-SHA-512]
INFO http://www.ietf.org/rfc/rfc2202.txt
INFO Test Case 1
OK hmac#sha224(repeat("\x0b", 20), "Hi There") ==# "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"
OK hmac#sha256(repeat("\x0b", 20), "Hi There") ==# "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
OK hmac#sha384(repeat("\x0b", 20), "Hi There") ==# "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
OK hmac#sha512(repeat("\x0b", 20), "Hi There") ==# "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
INFO Test Case 2
OK hmac#sha224("Jefe", "what do ya want for nothing?") ==# "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"
OK hmac#sha256("Jefe", "what do ya want for nothing?") ==# "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
OK hmac#sha384("Jefe", "what do ya want for nothing?") ==# "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
OK hmac#sha512("Jefe", "what do ya want for nothing?") ==# "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
INFO Test Case 3
OK hmac#sha224(repeat("\xaa", 20), repeat("\xdd", 50)) ==# "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea"
OK hmac#sha256(repeat("\xaa", 20), repeat("\xdd", 50)) ==# "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
OK hmac#sha384(repeat("\xaa", 20), repeat("\xdd", 50)) ==# "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"
OK hmac#sha512(repeat("\xaa", 20), repeat("\xdd", 50)) ==# "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
INFO Test Case 4
OK hmac#sha224(bytes#hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"), repeat("\xcd", 50)) ==# "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a"
OK hmac#sha256(bytes#hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"), repeat("\xcd", 50)) ==# "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
OK hmac#sha384(bytes#hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"), repeat("\xcd", 50)) ==# "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"
OK hmac#sha512(bytes#hex2bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"), repeat("\xcd", 50)) ==# "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
INFO Test Case 5
OK hmac#sha224(repeat("\x0c", 20), "Test With Truncation") =~# "^0e2aea68a90c8d37c988bcdb9fca6fa8"
OK hmac#sha256(repeat("\x0c", 20), "Test With Truncation") =~# "^a3b6167473100ee06e0c796c2955552b"
OK hmac#sha384(repeat("\x0c", 20), "Test With Truncation") =~# "^3abf34c3503b2a23a46efc619baef897"
OK hmac#sha512(repeat("\x0c", 20), "Test With Truncation") =~# "^415fad6271580a531d4179bc891d87a6"
INFO Test Case 6
OK hmac#sha224(repeat("\xaa", 131), "Test Using Larger Than Block-Size Key - Hash Key First") ==# "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"
OK hmac#sha256(repeat("\xaa", 131), "Test Using Larger Than Block-Size Key - Hash Key First") ==# "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
OK hmac#sha384(repeat("\xaa", 131), "Test Using Larger Than Block-Size Key - Hash Key First") ==# "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
OK hmac#sha512(repeat("\xaa", 131), "Test Using Larger Than Block-Size Key - Hash Key First") ==# "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
INFO Test Case 7
OK hmac#sha224(repeat("\xaa", 131), "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.") ==# "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"
OK hmac#sha256(repeat("\xaa", 131), "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.") ==# "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
OK hmac#sha384(repeat("\xaa", 131), "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.") ==# "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"
OK hmac#sha512(repeat("\xaa", 131), "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.") ==# "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"

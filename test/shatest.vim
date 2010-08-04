source <sfile>:p:h/test.vim
INFO SHATEST
function! _shatest(which, input, repeat, extrabits, numberExtrabits)
  let usha = hashlib#{a:which}#new()
  for i in range(a:repeat)
    call usha.update(a:input)
  endfor
  if a:numberExtrabits
    call usha.finalbits(a:extrabits, a:numberExtrabits)
  endif
  return usha.hexdigest()
endfunction
INFO SHA1
OK _shatest("sha1", "abc", 1, 0, 0) ==# "a9993e364706816aba3e25717850c26c9cd0d89d"
OK _shatest("sha1", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1, 0, 0) ==# "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
"OK _sha1test("a", 1000000, 0, 0) ==# "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
OK _shatest("sha1", "0123456701234567012345670123456701234567012345670123456701234567", 10, 0, 0) ==# "dea356a2cddd90c7a7ecedc5ebb563934f460452"
OK _shatest("sha1", "", 0, 0x9b, 5) ==# "29826b003b906e660eff4027ce98af3531ac75ba"
OK _shatest("sha1", "\x5e", 1, 0, 0) ==# "5e6f80a34a9798cafc6a5db96cc57ba4c4db59c2"
OK _shatest("sha1", bytes#hex2bytes("49b2aec2594bbe3a3b117542d94ac8"), 1, 0x80, 3) ==# "6239781e03729919c01955b3ffa8acb60b988340"
OK _shatest("sha1", bytes#hex2bytes("9a7dfdf1ecead06ed646aa55fe757146"), 1, 0, 0) ==# "82abff6605dbe1c17def12a394fa22a82b544a35"
OK _shatest("sha1",
      \ bytes#hex2bytes(
      \     "65f932995ba4ce2cb1b4a2e71ae70220"
      \   . "aacec8962dd4499cbd7c887a94eaaa10"
      \   . "1ea5aabc529b4e7e43665a5af2cd03fe"
      \   . "678ea6a5005bba3b082204c28b9109f4"
      \   . "69dac92aaab3aa7c11a1b32a"),
      \ 1, 0xE0, 3) ==# "8c5b2a5ddae5a97fc7f9d85661c672adbf7933d4"
OK _shatest("sha1",
      \ bytes#hex2bytes(
      \     "f78f92141bcd170ae89b4fba15a1d59f"
      \   . "3fd84d223c9251bdacbbae61d05ed115"
      \   . "a06a7ce117b7beead24421ded9c32592"
      \   . "bd57edeae39c39fa1fe8946a84d0cf1f"
      \   . "7beead1713e2e0959897347f67c80b04"
      \   . "00c209815d6b10a683836fd5562a56ca"
      \   . "b1a28e81b6576654631cf16566b86e3b"
      \   . "33a108b05307c00aff14a768ed735060"
      \   . "6a0f85e6a91d396f5b5cbe577f9b3880"
      \   . "7c7d523d6d792f6ebc24a4ecf2b3a427"
      \   . "cdbbfb"),
      \ 1, 0, 0) ==# "cb0082c8f197d260991ba6a460e76e202bad27b3"
INFO SHA224
OK _shatest("sha224", "abc", 1, 0, 0) ==# "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
OK _shatest("sha224", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1, 0, 0) ==# "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
"OK _shatest("sha224", "a", 1000000, 0, 0) ==# "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
OK _shatest("sha224", "0123456701234567012345670123456701234567012345670123456701234567", 10, 0, 0) ==# "567f69f168cd7844e65259ce658fe7aadfa25216e68eca0eb7ab8262"
OK _shatest("sha224", "", 0, 0x68, 5) ==# "e3b048552c3c387bcab37f6eb06bb79b96a4aee5ff27f51531a9551c"
OK _shatest("sha224", "\x07", 1, 0, 0) ==# "00ecd5f138422b8ad74c9799fd826c531bad2fcabc7450bee2aa8c2a"
OK _shatest("sha224", bytes#hex2bytes("f07006f25a0bea68cd76a29587c28d"), 1, 0xA0, 3) ==# "1b01db6cb4a9e43ded1516beb3db0b87b6d1ea43187462c608137150"
OK _shatest("sha224", bytes#hex2bytes("18804005dd4fbd1556299d6f9d93df62"), 1, 0, 0) ==# "df90d78aa78821c99b40ba4c966921accd8ffb1e98ac388e56191db1"
OK _shatest("sha224",
      \ bytes#hex2bytes(
      \   "a2be6e463281090294d9ce9482656942"
      \ . "3a3a305ed5e2116cd4a4c987fc065700"
      \ . "6491b149ccd4b51130ac62b19dc248c7"
      \ . "44543d20cd3952dced1f06cc3b18b91f"
      \ . "3f55633ecc3085f4907060d2"),
      \ 1, 0xE0, 3) ==# "54bea6eab8195a2eb0a7906a4b4a876666300eefbd1f3b8474f9cd57"
OK _shatest("sha224",
      \ bytes#hex2bytes(
      \   "55b210079c61b53add520622d1ac97d5"
      \ . "cdbe8cb33aa0ae344517bee4d7ba09ab"
      \ . "c8533c5250887a43bebbac906c2e1837"
      \ . "f26b36a59ae3be7814d506896b718b2a"
      \ . "383ecdac16b96125553f416ff32c6674"
      \ . "c74599a9005386d9ce1112245f48ee47"
      \ . "0d396c1ed63b92670ca56ec84deea814"
      \ . "b6135eca54392bdedb9489bc9b875a8b"
      \ . "af0dc1ae785736914ab7daa264bc079d"
      \ . "269f2c0d7eddd810a426145a0776f67c"
      \ . "878273"),
      \ 1, 0, 0) ==# "0b31894ec8937ad9b91bdfbcba294d9adefaa18e09305e9f20d5c3a4"
INFO SHA256
OK _shatest("sha256", "abc", 1, 0, 0) ==# "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
OK _shatest("sha256", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1, 0, 0) ==# "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
"OK _shatest("sha256", "a", 1000000, 0, 0) ==# "594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5"
OK _shatest("sha256", "0123456701234567012345670123456701234567012345670123456701234567", 10, 0, 0) ==# "594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5"
OK _shatest("sha256", "", 0, 0x68, 5) ==# "d6d3e02a31a84a8caa9718ed6c2057be09db45e7823eb5079ce7a573a3760f95"
OK _shatest("sha256", "\x19", 1, 0, 0) ==# "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4"
OK _shatest("sha256", bytes#hex2bytes("be2746c6db52765fdb2f88700f9a73"), 1, 0x60, 3) ==# "77ec1dc89c821ff2a1279089fa091b35b8cd960bcaf7de01c6a7680756beb972"
OK _shatest("sha256", bytes#hex2bytes("e3d72570dcdd787ce3887ab2cd684652"), 1, 0, 0) ==# "175ee69b02ba9b58e2b0a5fd13819cea573f3940a94f825128cf4209beabb4e8"
OK _shatest("sha256",
      \ bytes#hex2bytes(
      \   "3e740371c810c2b99fc04e804907ef7c"
      \ . "f26be28b57cb58a3e2f3c007166e49c1"
      \ . "2e9ba34c0104069129ea761564254570"
      \ . "3a2bd901e16eb0e05deba014ebff6406"
      \ . "a07d54364eff742da779b0b3"),
      \ 1, 0xA0, 3) ==# "3e9ad6468bbbad2ac3c2cdc292e018ba5fd70b960cf1679777fce708fdb066e9"
OK _shatest("sha256",
      \ bytes#hex2bytes(
      \   "8326754e2277372f4fc12b20527afef0"
      \ . "4d8a056971b11ad57123a7c137760000"
      \ . "d7bef6f3c1f7a9083aa39d810db31077"
      \ . "7dab8b1e7f02b84a26c773325f8b2374"
      \ . "de7a4b5a58cb5c5cf35bcee6fb946e5b"
      \ . "d694fa593a8beb3f9d6592ecedaa66ca"
      \ . "82a29d0c51bcf9336230e5d784e4c0a4"
      \ . "3f8d79a30a165cbabe452b774b9c7109"
      \ . "a97d138f129228966f6c0adc106aad5a"
      \ . "9fdd30825769b2c671af6759df28eb39"
      \ . "3d54d6"),
      \ 1, 0, 0) ==# "97dbca7df46d62c8a422c941dd7e835b8ad3361763f7e9b2d95f4f0da6e1ccbc"
INFO SHA384
OK _shatest("sha384", "abc", 1, 0, 0) ==# "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
OK _shatest("sha384", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1, 0, 0) ==# "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
"OK _shatest("sha384", "a", 1000000, 0, 0) ==# "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
OK _shatest("sha384", "0123456701234567012345670123456701234567012345670123456701234567", 10, 0, 0) ==# "2fc64a4f500ddb6828f6a3430b8dd72a368eb7f3a8322a70bc84275b9c0b3ab00d27a5cc3c2d224aa6b61a0d79fb4596"
OK _shatest("sha384", "", 0, 0x10, 5) ==# "8d17be79e32b6718e07d8a603eb84ba0478f7fcfd1bb93995f7d1149e09143ac1ffcfc56820e469f3878d957a15a3fe4"
OK _shatest("sha384", "\xb9", 1, 0, 0) ==# "bc8089a19007c0b14195f4ecc74094fec64f01f90929282c2fb392881578208ad466828b1c6c283d2722cf0ad1ab6938"
OK _shatest("sha384", bytes#hex2bytes("8bc500c77ceed9879da989107ce0aa"), 1, 0xA0, 3) ==# "d8c43b38e12e7c42a7c9b810299fd6a770bef30920f17532a898de62c7a07e4293449c0b5fa70109f0783211cfc4bce3"
OK _shatest("sha384", bytes#hex2bytes("a41c497779c0375ff10a7f4e08591739"), 1, 0, 0) ==# "c9a68443a005812256b8ec76b00516f0dbb74fab26d665913f194b6ffb0e91ea9967566b58109cbc675cc208e4c823f7"
OK _shatest("sha384",
      \ bytes#hex2bytes(
      \   "68f501792dea9796767022d93da71679"
      \ . "309920fa1012aea357b2b1331d40a1d0"
      \ . "3c41c240b3c9a75b4892f4c0724b68c8"
      \ . "75321ab8cfe5023bd375bc0f94bd89fe"
      \ . "04f297105d7b82ffc0021aeb1ccb674f"
      \ . "5244ea3497de26a4191c5f62e5e9a2d8"
      \ . "082f0551f4a5306826e91cc006ce1bf6"
      \ . "0ff719d42fa521c871cd2394d96ef446"
      \ . "8f21966b41f2ba80c26e83a9"),
      \ 1, 0xE0, 3) ==# "5860e8de91c21578bb4174d227898a98e0b45c4c760f009549495614daedc0775d92d11d9f8ce9b064eeac8dafc3a297"
OK _shatest("sha384",
      \ bytes#hex2bytes(
      \   "399669e28f6b9c6dbcbb6912ec10ffcf"
      \ . "74790349b7dc8fbe4a8e7b3b5621db0f"
      \ . "3e7dc87f823264bbe40d1811c9ea2061"
      \ . "e1c84ad10a23fac1727e7202fc3f5042"
      \ . "e6bf58cba8a2746e1f64f9b9ea352c71"
      \ . "1507053cf4e5339d52865f25cc22b5e8"
      \ . "7784a12fc961d66cb6e89573199a2ce6"
      \ . "565cbdf13dca403832cfcb0e8b7211e8"
      \ . "3af32a11ac17929ff1c073a51cc027aa"
      \ . "edeff85aad7c2b7c5a803e2404d96d2a"
      \ . "77357bda1a6daeed17151cb9bc5125a4"
      \ . "22e941de0ca0fc5011c23ecffefdd096"
      \ . "76711cf3db0a3440720e1615c1f22fbc"
      \ . "3c721de521e1b99ba1bd557740864214"
      \ . "7ed096"),
      \ 1, 0 , 0) ==# "4f440db1e6edd2899fa335f09515aa025ee177a79f4b4aaf38e42b5c4de660f5de8fb2a5b2fbd2a3cbffd20cff1288c0"
INFO SHA512
OK _shatest("sha512", "abc", 1, 0, 0) ==# "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
OK _shatest("sha512", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1, 0, 0) ==# "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
"OK _shatest("sha512", "a", 1000000, 0, 0) ==# "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
OK _shatest("sha512", "0123456701234567012345670123456701234567012345670123456701234567", 10, 0, 0) ==# "89d05ba632c699c31231ded4ffc127d5a894dad412c0e024db872d1abd2ba8141a0f85072a9be1e2aa04cf33c765cb510813a39cd5a84c4acaa64d3f3fb7bae9"
OK _shatest("sha512", "", 0, 0xB0, 5) ==# "d4ee29a9e90985446b913cf1d1376c836f4be2c1cf3cada0720a6bf4857d886a7ecb3c4e4c0fa8c7f95214e41dc1b0d21b22a84cc03bf8ce4845f34dd5bdbad4"
OK _shatest("sha512", "\xD0", 1, 0, 0) ==# "9992202938e882e73e20f6b69e68a0a7149090423d93c81bab3f21678d4aceeee50e4e8cafada4c85a54ea8306826c4ad6e74cece9631bfa8a549b4ab3fbba15"
OK _shatest("sha512", bytes#hex2bytes("08ecb52ebae1f7422db62bcd542670"), 1, 0x80, 3) ==# "ed8dc78e8b01b69750053dbb7a0a9eda0fb9e9d292b1ed715e80a7fe290a4e16664fd913e85854400c5af05e6dad316b7359b43e64f8bec3c1f237119986bbb6"
OK _shatest("sha512", bytes#hex2bytes("8d4e3c0e3889191491816e9d98bff0a0"), 1, 0, 0) ==# "cb0b67a4b8712cd73c9aabc0b199e9269b20844afb75acbdd1c153c9828924c3ddedaafe669c5fdd0bc66f630f6773988213eb1b16f517ad0de4b2f0c95c90f8"
OK _shatest("sha512",
      \ bytes#hex2bytes(
      \   "3addec85593216d1619aa02d9756970b"
      \ . "fc70ace2744f7c6b2788151028f7b6a2"
      \ . "550fd74a7e6e69c2c9b45fc454966dc3"
      \ . "1d2e10da1f95ce02beb4bf8765574cbd"
      \ . "6e8337ef420adc98c15cb6d5e4a0241b"
      \ . "a0046d250e510231cac2046c991606ab"
      \ . "4ee4145bee2ff4bb123aab498d9d4479"
      \ . "4f99ccad89a9a1621259eda70a5b6dd4"
      \ . "bdd87778c9043b9384f54906"),
      \ 1, 0x80, 3) ==# "32ba76fc30eaa0208aeb50ffb5af1864fdbf17902a4dc0a682c61fcea6d92b783267b21080301837f59de79c6b337db2526f8a0a510e5e53cafed4355fe7c2f1"
OK _shatest("sha512", 
      \ bytes#hex2bytes(
      \   "a55f20c411aad132807a502d65824e31"
      \ . "a2305432aa3d06d3e282a8d84e0de1de"
      \ . "6974bf495469fc7f338f8054d58c26c4"
      \ . "9360c3e87af56523acf6d89d03e56ff2"
      \ . "f868002bc3e431edc44df2f0223d4bb3"
      \ . "b243586e1a7d924936694fcbbaf88d95"
      \ . "19e4eb50a644f8e4f95eb0ea95bc4465"
      \ . "c8821aacd2fe15ab4981164bbb6dc32f"
      \ . "969087a145b0d9cc9c67c22b76329941"
      \ . "9cc4128be9a077b3ace634064e6d9928"
      \ . "3513dc06e7515d0d73132e9a0dc6d3b1"
      \ . "f8b246f1a98a3fc72941b1e3bb2098e8"
      \ . "bf16f268d64f0b0f4707fe1ea1a1791b"
      \ . "a2f3c0c758e5f551863a96c949ad47d7"
      \ . "fb40d2"),
      \ 1, 0, 0) ==# "c665befb36da189d78822d10528cbf3b12b3eef726039909c1a16a270d48719377966b957a878e720584779a62825c18da26415e49a7176a894e7510fd1451f5"

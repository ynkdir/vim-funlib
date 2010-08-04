" sha1 digest calculator    vim:set fdm=marker:
" This is a port of rfc4634 sha1 function.
" [US Secure Hash Algorithms (SHA and HMAC-SHA)]
" http://www.ietf.org/rfc/rfc4634.txt
" Last Change:  2010-08-05
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>

let s:save_cpo = &cpo
set cpo&vim

function! hashlib#sha1#new(...)
  let data = get(a:000, 0, [])
  return s:sha1.new(data)
endfunction

let s:sha1 = {}

function s:sha1.new(...)
  let data = get(a:000, 0, [])
  let obj = deepcopy(self)
  let obj.context = deepcopy(s:SHA1Context)
  let err = s:SHA1Reset(obj.context)
  if err
    throw printf("SHA1Reset Error %d", err)
  endif
  call obj.update(data)
  return obj
endfunction

function s:sha1.update(data)
  let data = (type(a:data) == type("") ? bytes#str2bytes(a:data) : a:data)
  let err = s:SHA1Input(self.context, data, len(data))
  if err
    throw printf("SHA1Input Error %d", err)
  endif
  return self
endfunction

function s:sha1.digest()
  let digest = repeat([0], s:SHA1HashSize)
  let err = s:SHA1Result(self.context, digest)
  if err
    throw printf("SHA1Result Error %d", err)
  endif
  return digest
endfunction

function s:sha1.hexdigest()
  return bytes#bytes2hex(self.digest())
endfunction

function s:sha1.copy()
  return deepcopy(self)
endfunction

function s:sha1.finalbits(bits, bitcount)
  let err = s:SHA1FinalBits(self.context, a:bits, a:bitcount)
  if err
    throw printf("SHA1FinalBits Error %d", err)
  endif
endfunction

" sha.h.vim {{{
"**************************** sha.h ****************************
"******************* See RFC 4634 for details ******************
"
" Description:
"     This file implements the Secure Hash Signature Standard
"     algorithms as defined in the National Institute of Standards
"     and Technology Federal Information Processing Standards
"     Publication (FIPS PUB) 180-1 published on April 17, 1995, 180-2
"     published on August 1, 2002, and the FIPS PUB 180-2 Change
"     Notice published on February 28, 2004.
"
"     A combined document showing all algorithms is available at
"             http://csrc.nist.gov/publications/fips/
"             fips180-2/fips180-2withchangenotice.pdf
"
"     The five hashes are defined in these sizes:
"             SHA-1           20 byte / 160 bit
"             SHA-224         28 byte / 224 bit
"             SHA-256         32 byte / 256 bit
"             SHA-384         48 byte / 384 bit
"             SHA-512         64 byte / 512 bit
"

"
" If you do not have the ISO standard stdint.h header file, then you
" must typedef the following:
"    name              meaning
"  uint64_t         unsigned 64 bit integer
"  uint32_t         unsigned 32 bit integer
"  uint8_t          unsigned 8 bit integer (i.e., unsigned char)
"  int_least16_t    integer of >= 16 bits
"

"
"  All SHA functions return one of these values.
"
" enum
let s:shaSuccess = 0
let s:shaNull = 1         " Null pointer parameter
let s:shaInputTooLong = 2 " input data too long
let s:shaStateError = 3   " called Input after FinalBits or Result
let s:shaBadParam = 4     " passed a bad parameter

"
" These constants hold size information for each of the SHA
" hashing operations
"
" enum
let s:SHA1_Message_Block_Size = 64
let s:SHA224_Message_Block_Size = 64
let s:SHA256_Message_Block_Size = 64
let s:SHA384_Message_Block_Size = 128
let s:SHA512_Message_Block_Size = 128
let s:USHA_Max_Message_Block_Size = s:SHA512_Message_Block_Size
let s:SHA1HashSize = 20
let s:SHA224HashSize = 28
let s:SHA256HashSize = 32
let s:SHA384HashSize = 48
let s:SHA512HashSize = 64
let s:USHAMaxHashSize = s:SHA512HashSize
let s:SHA1HashSizeBits = 160
let s:SHA224HashSizeBits = 224
let s:SHA256HashSizeBits = 256
let s:SHA384HashSizeBits = 384
let s:SHA512HashSizeBits = 512
let s:USHAMaxHashSizeBits = s:SHA512HashSizeBits

"
" These constants are used in the USHA (unified sha) functions.
"
"typedef enum SHAversion {
"    SHA1, SHA224, SHA256, SHA384, SHA512
"} SHAversion;
let s:SHA1 = 0
let s:SHA224 = 1
let s:SHA256 = 2
let s:SHA384 = 3
let s:SHA512 = 4

"
" This structure will hold context information for the SHA-1
" hashing operation.
"
"typedef struct SHA1Context {
"    uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest */
"
"    uint32_t Length_Low;                /* Message length in bits */
"    uint32_t Length_High;               /* Message length in bits */
"
"    int_least16_t Message_Block_Index;  /* Message_Block array index */
"                                        /* 512-bit message blocks */
"    uint8_t Message_Block[SHA1_Message_Block_Size];
"
"    int Computed;                       /* Is the digest computed? */
"    int Corrupted;                      /* Is the digest corrupted? */
"} SHA1Context;
let s:SHA1Context = {
      \ "Intermediate_Hash": repeat([0], s:SHA1HashSize / 4),
      \ "Length_Low": 0,
      \ "Length_High": 0,
      \ "Message_Block_Index": 0,
      \ "Message_Block": repeat([0], s:SHA1_Message_Block_Size),
      \ "Computed": 0,
      \ "Corrupted": 0,
      \ }

"
" This structure will hold context information for the SHA-256
" hashing operation.
"
"typedef struct SHA256Context {
"    uint32_t Intermediate_Hash[SHA256HashSize/4]; /* Message Digest */
"
"    uint32_t Length_Low;                /* Message length in bits */
"    uint32_t Length_High;               /* Message length in bits */
"
"    int_least16_t Message_Block_Index;  /* Message_Block array index */
"                                        /* 512-bit message blocks */
"    uint8_t Message_Block[SHA256_Message_Block_Size];
"
"    int Computed;                       /* Is the digest computed? */
"    int Corrupted;                      /* Is the digest corrupted? */
"} SHA256Context;
let s:SHA256Context = {
      \ "Intermediate_Hash": repeat([0], s:SHA256HashSize / 4),
      \ "Length_Low": 0,
      \ "Length_High": 0,
      \ "Message_Block_Index": 0,
      \ "Message_Block": repeat([0], s:SHA256_Message_Block_Size),
      \ "Computed": 0,
      \ "Corrupted": 0,
      \ }

"
" This structure will hold context information for the SHA-512
" hashing operation.
"
"typedef struct SHA512Context {
"#ifdef USE_32BIT_ONLY
"    uint32_t Intermediate_Hash[SHA512HashSize/4]; /* Message Digest  */
"    uint32_t Length[4];                 /* Message length in bits */
"#else /* !USE_32BIT_ONLY */
"    uint64_t Intermediate_Hash[SHA512HashSize/8]; /* Message Digest */
"    uint64_t Length_Low, Length_High;   /* Message length in bits */
"#endif /* USE_32BIT_ONLY */
"    int_least16_t Message_Block_Index;  /* Message_Block array index */
"                                        /* 1024-bit message blocks */
"    uint8_t Message_Block[SHA512_Message_Block_Size];
"
"    int Computed;                       /* Is the digest computed?*/
"    int Corrupted;                      /* Is the digest corrupted? */
"} SHA512Context;
let s:SHA512Context = {
      \ "Intermediate_Hash": repeat([0], s:SHA512HashSize / 4),
      \ "Length": repeat([0], 4),
      \ "Message_Block_Index": 0,
      \ "Message_Block": repeat([0], s:SHA512_Message_Block_Size),
      \ "Computed": 0,
      \ "Corrupted": 0,
      \ }

"
" This structure will hold context information for the SHA-224
" hashing operation. It uses the SHA-256 structure for computation.
"
"typedef struct SHA256Context SHA224Context;
let s:SHA224Context = s:SHA256Context

"
" This structure will hold context information for the SHA-384
" hashing operation. It uses the SHA-512 structure for computation.
"
"typedef struct SHA512Context SHA384Context;
let s:SHA384Context = s:SHA512Context

"
" This structure holds context information for all SHA
" hashing operations.
"
"typedef struct USHAContext {
"    int whichSha;               /* which SHA is being used */
"    union {
"      SHA1Context sha1Context;
"      SHA224Context sha224Context; SHA256Context sha256Context;
"      SHA384Context sha384Context; SHA512Context sha512Context;
"    } ctx;
"} USHAContext;
let s:USHAContext = {
      \ "whichSha": 0,
      \ "ctx": {},
      \ }

"
" This structure will hold context information for the HMAC
" keyed hashing operation.
"
"typedef struct HMACContext {
"    int whichSha;               /* which SHA is being used */
"    int hashSize;               /* hash size of SHA being used */
"    int blockSize;              /* block size of SHA being used */
"    USHAContext shaContext;     /* SHA context */
"    unsigned char k_opad[USHA_Max_Message_Block_Size];
"                        /* outer padding - key XORd with opad */
"} HMACContext;
let s:HMACContext = {
      \ "whichSha": 0,
      \ "hashSize": 0,
      \ "blockSize": 0,
      \ "shaContext": {},
      \ "k_opad": repeat([0], s:USHA_Max_Message_Block_Size),
      \ }

" }}}
" sha-private.h.vim {{{
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

" }}}
" sha1.c.vim {{{
"**************************** sha1.c ****************************
"******************** See RFC 4634 for details ******************
"
"  Description:
"      This file implements the Secure Hash Signature Standard
"      algorithms as defined in the National Institute of Standards
"      and Technology Federal Information Processing Standards
"      Publication (FIPS PUB) 180-1 published on April 17, 1995, 180-2
"      published on August 1, 2002, and the FIPS PUB 180-2 Change
"      Notice published on February 28, 2004.
"
"      A combined document showing all algorithms is available at
"              http://csrc.nist.gov/publications/fips/
"              fips180-2/fips180-2withchangenotice.pdf
"
"      The SHA-1 algorithm produces a 160-bit message digest for a
"      given data stream.  It should take about 2**n steps to find a
"      message with the same digest as a given message and
"      2**(n/2) to find any two messages with the same digest,
"      when n is the digest size in bits.  Therefore, this
"      algorithm can serve as a means of providing a
"      "fingerprint" for a message.
"
"  Portability Issues:
"      SHA-1 is defined in terms of 32-bit "words".  This code
"      uses <stdint.h> (included via "sha.h") to define 32 and 8
"      bit unsigned integer types.  If your C compiler does not
"      support 32 bit unsigned integers, this code is not
"      appropriate.
"
"  Caveats:
"      SHA-1 is designed to work with messages less than 2^64 bits
"      long. This implementation uses SHA1Input() to hash the bits
"      that are a multiple of the size of an 8-bit character, and then
"      uses SHA1FinalBits() to hash the final few bits of the input.
"

"
"  Define the SHA1 circular left shift macro
"
"#define SHA1_ROTL(bits,word) \
"                (((word) << (bits)) | ((word) >> (32-(bits))))
function! s:SHA1_ROTL(bits, word)
  return bitwise#or(bitwise#lshift(a:word, a:bits), bitwise#rshift(a:word, 32 - a:bits))
endfunction

"
" add "length" to the length
"
"static uint32_t addTemp;
"#define SHA1AddLength(context, length)                     \
"    (addTemp = (context)->Length_Low,                      \
"     (context)->Corrupted =                                \
"        (((context)->Length_Low += (length)) < addTemp) && \
"        (++(context)->Length_High == 0) ? 1 : 0)
function! s:SHA1AddLength(context, length)
  let addTemp = a:context.Length_Low
  let a:context.Length_Low += a:length
  if bitwise#cmp(a:context.Length_Low, addTemp) < 0
    let a:context.Length_High += 1
    if a:context.Length_High == 0
      let a:context.Corrupted = 1
    else
      let a:context.Corrupted = 0
    endif
  else
    let a:context.Corrupted = 0
  endif
endfunction

" Local Function Prototypes
"static void SHA1Finalize(SHA1Context *context, uint8_t Pad_Byte);
"static void SHA1PadMessage(SHA1Context *, uint8_t Pad_Byte);
"static void SHA1ProcessMessageBlock(SHA1Context *);

"
"  SHA1Reset
"
"  Description:
"      This function will initialize the SHA1Context in preparation
"      for computing a new SHA1 message digest.
"
"  Parameters:
"      context: [in/out]
"          The context to reset.
"
"  Returns:
"      sha Error Code.
"
"
"int SHA1Reset(SHA1Context *context)
"{
"    if (!context)
"        return shaNull;
"
"    context->Length_Low             = 0;
"    context->Length_High            = 0;
"    context->Message_Block_Index    = 0;
"
"    /* Initial Hash Values: FIPS-180-2 section 5.3.1 */
"    context->Intermediate_Hash[0]   = 0x67452301;
"    context->Intermediate_Hash[1]   = 0xEFCDAB89;
"    context->Intermediate_Hash[2]   = 0x98BADCFE;
"    context->Intermediate_Hash[3]   = 0x10325476;
"    context->Intermediate_Hash[4]   = 0xC3D2E1F0;
"
"    context->Computed   = 0;
"    context->Corrupted  = 0;
"
"    return shaSuccess;
"}
function! s:SHA1Reset(context)
  if empty(a:context)
    return s:shaNull
  endif

  let a:context.Length_Low            = 0
  let a:context.Length_High           = 0
  let a:context.Message_Block_Index   = 0

  let a:context.Intermediate_Hash[0]  = 0x67452301
  let a:context.Intermediate_Hash[1]  = 0xEFCDAB89
  let a:context.Intermediate_Hash[2]  = 0x98BADCFE
  let a:context.Intermediate_Hash[3]  = 0x10325476
  let a:context.Intermediate_Hash[4]  = 0xC3D2E1F0

  let a:context.Computed = 0
  let a:context.Corrupted = 0

  return s:shaSuccess
endfunction

"
"  SHA1Input
"
"  Description:
"      This function accepts an array of octets as the next portion
"      of the message.
"
"  Parameters:
"      context: [in/out]
"          The SHA context to update
"      message_array: [in]
"          An array of characters representing the next portion of
"          the message.
"      length: [in]
"          The length of the message in message_array
"
"  Returns:
"      sha Error Code.
"
"
"int SHA1Input(SHA1Context *context,
"    const uint8_t *message_array, unsigned length)
"{
"  if (!length)
"    return shaSuccess;
"
"  if (!context || !message_array)
"    return shaNull;
"
"  if (context->Computed) {
"    context->Corrupted = shaStateError;
"    return shaStateError;
"  }
"
"  if (context->Corrupted)
"     return context->Corrupted;
"
"  while (length-- && !context->Corrupted) {
"    context->Message_Block[context->Message_Block_Index++] =
"      (*message_array & 0xFF);
"
"    if (!SHA1AddLength(context, 8) &&
"      (context->Message_Block_Index == SHA1_Message_Block_Size))
"      SHA1ProcessMessageBlock(context);
"
"    message_array++;
"  }
"
"  return shaSuccess;
"}
function! s:SHA1Input(context, message_array, length)
  if !a:length
    return s:shaSuccess
  endif

  if empty(a:context) || empty(a:message_array)
    return s:shaNull
  endif

  if a:context.Computed
    let a:context.Corrupted = s:shaStateError
    return s:shaStateError
  endif

  if a:context.Corrupted
    return a:context.Corrupted
  endif

  let length = a:length
  let message_array_index = 0
  while length > 0 && !a:context.Corrupted
    let a:context.Message_Block[a:context.Message_Block_Index] =
          \ bitwise#and(a:message_array[message_array_index], 0xFF)
    let a:context.Message_Block_Index += 1

    if !s:SHA1AddLength(a:context, 8) &&
          \ a:context.Message_Block_Index == s:SHA1_Message_Block_Size
      call s:SHA1ProcessMessageBlock(a:context)
    endif
    let message_array_index += 1
    let length -= 1
  endwhile

  return s:shaSuccess
endfunction

"
" SHA1FinalBits
"
" Description:
"   This function will add in any final bits of the message.
"
" Parameters:
"   context: [in/out]
"     The SHA context to update
"   message_bits: [in]
"     The final bits of the message, in the upper portion of the
"     byte. (Use 0b###00000 instead of 0b00000### to input the
"     three bits ###.)
"   length: [in]
"     The number of bits in message_bits, between 1 and 7.
"
" Returns:
"   sha Error Code.
"
"int SHA1FinalBits(SHA1Context *context, const uint8_t message_bits,
"    unsigned int length)
"{
"  uint8_t masks[8] = {
"      /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
"      /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
"      /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
"      /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
"  };
"  uint8_t markbit[8] = {
"      /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
"      /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
"      /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
"      /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
"  };
"
"  if (!length)
"    return shaSuccess;
"
"  if (!context)
"    return shaNull;
"
"  if (context->Computed || (length >= 8) || (length == 0)) {
"    context->Corrupted = shaStateError;
"    return shaStateError;
"  }
"
"  if (context->Corrupted)
"     return context->Corrupted;
"
"  SHA1AddLength(context, length);
"  SHA1Finalize(context,
"    (uint8_t) ((message_bits & masks[length]) | markbit[length]));
"
"  return shaSuccess;
"}
function! s:SHA1FinalBits(context, message_bits, length)
  let masks = [
        \ 0x00, 0x80,
        \ 0xC0, 0xE0,
        \ 0xF0, 0xF8,
        \ 0xFC, 0xFE
        \ ]
  let markbit = [
        \ 0x80, 0x40,
        \ 0x20, 0x10,
        \ 0x08, 0x04,
        \ 0x02, 0x01
        \ ]

  if !a:length
    return s:shaSuccess
  endif

  if empty(a:context)
    return s:shaNull
  endif

  if a:context.Computed || a:length >= 8 || a:length == 0
    let a:context.Corrupted = s:shaStateError
    return s:shaStateError
  endif

  if a:context.Corrupted
    return a:context.Corrupted
  endif

  call s:SHA1AddLength(a:context, a:length)
  call s:SHA1Finalize(a:context,
        \ bitwise#uint8(bitwise#or(bitwise#and(a:message_bits, masks[a:length]), markbit[a:length])))

  return s:shaSuccess
endfunction

"
" SHA1Result
"
" Description:
"   This function will return the 160-bit message digest into the
"   Message_Digest array provided by the caller.
"   NOTE: The first octet of hash is stored in the 0th element,
"      the last octet of hash in the 19th element.
"
" Parameters:
"   context: [in/out]
"     The context to use to calculate the SHA-1 hash.
"   Message_Digest: [out]
"     Where the digest is returned.
"
" Returns:
"   sha Error Code.
"
"
"int SHA1Result(SHA1Context *context,
"    uint8_t Message_Digest[SHA1HashSize])
"{
"  int i;
"
"  if (!context || !Message_Digest)
"    return shaNull;
"
"  if (context->Corrupted)
"    return context->Corrupted;
"
"  if (!context->Computed)
"    SHA1Finalize(context, 0x80);
"
"  for (i = 0; i < SHA1HashSize; ++i)
"    Message_Digest[i] = (uint8_t) (context->Intermediate_Hash[i>>2]
"              >> 8 * ( 3 - ( i & 0x03 ) ));
"
"  return shaSuccess;
"}
function! s:SHA1Result(context, Message_Digest)
  if empty(a:context) || empty(a:Message_Digest)
    return s:shaNull
  endif

  if a:context.Corrupted
    return a:context.Corrupted
  endif

  if !a:context.Computed
    call s:SHA1Finalize(a:context, 0x80)
  endif

  for i in range(s:SHA1HashSize)
    let a:Message_Digest[i] = bitwise#uint8(
          \ bitwise#rshift(a:context.Intermediate_Hash[i/4], 8 * (3 - (i % 4))))
  endfor

  return s:shaSuccess
endfunction

"
" SHA1Finalize
"
" Description:
"   This helper function finishes off the digest calculations.
"
" Parameters:
"   context: [in/out]
"     The SHA context to update
"   Pad_Byte: [in]
"     The last byte to add to the digest before the 0-padding
"     and length. This will contain the last bits of the message
"     followed by another single bit. If the message was an
"     exact multiple of 8-bits long, Pad_Byte will be 0x80.
"
" Returns:
"   sha Error Code.
"
"
"static void SHA1Finalize(SHA1Context *context, uint8_t Pad_Byte)
"{
"  int i;
"  SHA1PadMessage(context, Pad_Byte);
"  /* message may be sensitive, clear it out */
"  for (i = 0; i < SHA1_Message_Block_Size; ++i)
"    context->Message_Block[i] = 0;
"  context->Length_Low = 0;  /* and clear length */
"  context->Length_High = 0;
"  context->Computed = 1;
"}
function! s:SHA1Finalize(context, Pad_Byte)
  call s:SHA1PadMessage(a:context, a:Pad_Byte)
  for i in range(s:SHA1_Message_Block_Size)
    let a:context.Message_Block[i] = 0
  endfor
  let a:context.Length_Low = 0
  let a:context.Length_High = 0
  let a:context.Computed = 1
endfunction

"
" SHA1PadMessage
"
" Description:
"   According to the standard, the message must be padded to an
"   even 512 bits. The first padding bit must be a '1'. The last
"   64 bits represent the length of the original message. All bits
"   in between should be 0. This helper function will pad the
"   message according to those rules by filling the Message_Block
"   array accordingly. When it returns, it can be assumed that the
"   message digest has been computed.
"
" Parameters:
"   context: [in/out]
"     The context to pad
"   Pad_Byte: [in]
"     The last byte to add to the digest before the 0-padding
"     and length. This will contain the last bits of the message
"     followed by another single bit. If the message was an
"     exact multiple of 8-bits long, Pad_Byte will be 0x80.
"
" Returns:
"   Nothing.
"
"static void SHA1PadMessage(SHA1Context *context, uint8_t Pad_Byte)
"{
"  /*
"   * Check to see if the current message block is too small to hold
"   * the initial padding bits and length. If so, we will pad the
"   * block, process it, and then continue padding into a second
"   * block.
"   */
"  if (context->Message_Block_Index >= (SHA1_Message_Block_Size - 8)) {
"    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
"    while (context->Message_Block_Index < SHA1_Message_Block_Size)
"      context->Message_Block[context->Message_Block_Index++] = 0;
"
"    SHA1ProcessMessageBlock(context);
"  } else
"    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
"
"  while (context->Message_Block_Index < (SHA1_Message_Block_Size - 8))
"    context->Message_Block[context->Message_Block_Index++] = 0;
"
"  /*
"   * Store the message length as the last 8 octets
"   */
"  context->Message_Block[56] = (uint8_t) (context->Length_High >> 24);
"  context->Message_Block[57] = (uint8_t) (context->Length_High >> 16);
"  context->Message_Block[58] = (uint8_t) (context->Length_High >> 8);
"  context->Message_Block[59] = (uint8_t) (context->Length_High);
"  context->Message_Block[60] = (uint8_t) (context->Length_Low >> 24);
"  context->Message_Block[61] = (uint8_t) (context->Length_Low >> 16);
"  context->Message_Block[62] = (uint8_t) (context->Length_Low >> 8);
"  context->Message_Block[63] = (uint8_t) (context->Length_Low);
"
"  SHA1ProcessMessageBlock(context);
"}
function! s:SHA1PadMessage(context, Pad_Byte)
  if a:context.Message_Block_Index >= (s:SHA1_Message_Block_Size - 8)
    let a:context.Message_Block[a:context.Message_Block_Index] = a:Pad_Byte
    let a:context.Message_Block_Index += 1
    while a:context.Message_Block_Index < s:SHA1_Message_Block_Size
      let a:context.Message_Block[a:context.Message_Block_Index] = 0
      let a:context.Message_Block_Index += 1
    endwhile
    call s:SHA1ProcessMessageBlock(a:context)
  else
    let a:context.Message_Block[a:context.Message_Block_Index] = a:Pad_Byte
    let a:context.Message_Block_Index += 1
  endif

  while a:context.Message_Block_Index < (s:SHA1_Message_Block_Size - 8)
    let a:context.Message_Block[a:context.Message_Block_Index] = 0
    let a:context.Message_Block_Index += 1
  endwhile

  let a:context.Message_Block[56] = bitwise#uint8(bitwise#rshift(a:context.Length_High, 24))
  let a:context.Message_Block[57] = bitwise#uint8(bitwise#rshift(a:context.Length_High, 16))
  let a:context.Message_Block[58] = bitwise#uint8(bitwise#rshift(a:context.Length_High, 8))
  let a:context.Message_Block[59] = bitwise#uint8(a:context.Length_High)
  let a:context.Message_Block[60] = bitwise#uint8(bitwise#rshift(a:context.Length_Low, 24))
  let a:context.Message_Block[61] = bitwise#uint8(bitwise#rshift(a:context.Length_Low, 16))
  let a:context.Message_Block[62] = bitwise#uint8(bitwise#rshift(a:context.Length_Low, 8))
  let a:context.Message_Block[63] = bitwise#uint8(a:context.Length_Low)

  call s:SHA1ProcessMessageBlock(a:context)
endfunction

"
" SHA1ProcessMessageBlock
"
" Description:
"   This helper function will process the next 512 bits of the
"   message stored in the Message_Block array.
"
" Parameters:
"   None.
"
" Returns:
"   Nothing.
"
" Comments:
"   Many of the variable names in this code, especially the
"   single character names, were used because those were the
"   names used in the publication.
"
"static void SHA1ProcessMessageBlock(SHA1Context *context)
"{
"  /* Constants defined in FIPS-180-2, section 4.2.1 */
"  const uint32_t K[4] = {
"      0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
"  };
"  int        t;               /* Loop counter */
"  uint32_t   temp;            /* Temporary word value */
"  uint32_t   W[80];           /* Word sequence */
"  uint32_t   A, B, C, D, E;   /* Word buffers */
"
"  /*
"   * Initialize the first 16 words in the array W
"   */
"  for (t = 0; t < 16; t++) {
"    W[t]  = ((uint32_t)context->Message_Block[t * 4]) << 24;
"    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
"    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
"    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
"  }
"  for (t = 16; t < 80; t++)
"    W[t] = SHA1_ROTL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
"
"  A = context->Intermediate_Hash[0];
"  B = context->Intermediate_Hash[1];
"  C = context->Intermediate_Hash[2];
"  D = context->Intermediate_Hash[3];
"  E = context->Intermediate_Hash[4];
"
"  for (t = 0; t < 20; t++) {
"    temp = SHA1_ROTL(5,A) + SHA_Ch(B, C, D) + E + W[t] + K[0];
"    E = D;
"    D = C;
"    C = SHA1_ROTL(30,B);
"    B = A;
"    A = temp;
"  }
"
"  for (t = 20; t < 40; t++) {
"    temp = SHA1_ROTL(5,A) + SHA_Parity(B, C, D) + E + W[t] + K[1];
"    E = D;
"    D = C;
"    C = SHA1_ROTL(30,B);
"    B = A;
"    A = temp;
"  }
"
"  for (t = 40; t < 60; t++) {
"    temp = SHA1_ROTL(5,A) + SHA_Maj(B, C, D) + E + W[t] + K[2];
"    E = D;
"    D = C;
"    C = SHA1_ROTL(30,B);
"    B = A;
"    A = temp;
"  }
"
"  for (t = 60; t < 80; t++) {
"    temp = SHA1_ROTL(5,A) + SHA_Parity(B, C, D) + E + W[t] + K[3];
"    E = D;
"    D = C;
"    C = SHA1_ROTL(30,B);
"    B = A;
"    A = temp;
"  }
"
"  context->Intermediate_Hash[0] += A;
"  context->Intermediate_Hash[1] += B;
"  context->Intermediate_Hash[2] += C;
"  context->Intermediate_Hash[3] += D;
"  context->Intermediate_Hash[4] += E;
"
"  context->Message_Block_Index = 0;
"}
function! s:SHA1ProcessMessageBlock(context)
  let K = [
        \ 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
        \ ]
  let W = repeat([0], 80)

  for t in range(16)
    let W[t] = bitwise#or(bitwise#or(bitwise#or(
          \ bitwise#lshift(a:context.Message_Block[t * 4], 24),
          \ bitwise#lshift(a:context.Message_Block[t * 4 + 1], 16)),
          \ bitwise#lshift(a:context.Message_Block[t * 4 + 2], 8)),
          \ a:context.Message_Block[t * 4 + 3])
  endfor
  for t in range(16, 79)
    let W[t] = s:SHA1_ROTL(1, bitwise#xor(bitwise#xor(bitwise#xor(W[t-3], W[t-8]), W[t-14]), W[t-16]))
  endfor

  let A = a:context.Intermediate_Hash[0]
  let B = a:context.Intermediate_Hash[1]
  let C = a:context.Intermediate_Hash[2]
  let D = a:context.Intermediate_Hash[3]
  let E = a:context.Intermediate_Hash[4]

  for t in range(20)
    let temp = s:SHA1_ROTL(5,A) + s:SHA_Ch(B, C, D) + E + W[t] + K[0]
    let E = D
    let D = C
    let C = s:SHA1_ROTL(30,B)
    let B = A
    let A = temp
  endfor

  for t in range(20, 39)
    let temp = s:SHA1_ROTL(5,A) + s:SHA_Parity(B, C, D) + E + W[t] + K[1]
    let E = D
    let D = C
    let C = s:SHA1_ROTL(30,B)
    let B = A
    let A = temp
  endfor

  for t in range(40, 59)
    let temp = s:SHA1_ROTL(5,A) + s:SHA_Maj(B, C, D) + E + W[t] + K[2]
    let E = D
    let D = C
    let C = s:SHA1_ROTL(30,B)
    let B = A
    let A = temp
  endfor

  for t in range(60, 79)
    let temp = s:SHA1_ROTL(5,A) + s:SHA_Parity(B, C, D) + E + W[t] + K[3]
    let E = D
    let D = C
    let C = s:SHA1_ROTL(30,B)
    let B = A
    let A = temp
  endfor

  let a:context.Intermediate_Hash[0] += A
  let a:context.Intermediate_Hash[1] += B
  let a:context.Intermediate_Hash[2] += C
  let a:context.Intermediate_Hash[3] += D
  let a:context.Intermediate_Hash[4] += E

  let a:context.Message_Block_Index = 0
endfunction

" }}}

let &cpo = s:save_cpo
unlet s:save_cpo

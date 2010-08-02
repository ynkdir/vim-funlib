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


" [.ZIP File Format Specification]
" http://www.pkware.com/documents/casestudies/APPNOTE.TXT
" Last Change:  2010-10-02
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
" License:      This file is placed in the public domain.

function unzip#unzip(data)
  return s:Unzip.new(a:data).unzip()
endfunction

let s:LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50

let s:METHOD_NO_COMPRESSION = 0
let s:METHOD_SHRUNK = 1
let s:METHOD_FACTOR1 = 2
let s:METHOD_FACTOR2 = 3
let s:METHOD_FACTOR3 = 4
let s:METHOD_FACTOR4 = 5
let s:METHOD_IMPLODE = 6
let s:METHOD_RESERVED7 = 7
let s:METHOD_DEFLATE = 8
let s:METHOD_DEFLATE64 = 9
let s:METHOD_OLD_IBM_TERSE = 10
let s:METHOD_RESERVED11 = 11
let s:METHOD_BZIP2 = 12
let s:METHOD_RESERVED13 = 13
let s:METHOD_LZMA = 14
let s:METHOD_RESERVED15 = 15
let s:METHOD_RESERVED16 = 16
let s:METHOD_RESERVED17 = 17
let s:METHOD_NEW_IBM_TERSE = 18
let s:METHOD_IBM_LZ77_Z = 19
let s:METHOD_WEVPACK = 97
let s:METHOD_PPMD = 98

let s:FLAG_ENCRYPTED = 0x0001
let s:FLAG_CRC32 = 0x0004

let s:Unzip = {}

function s:Unzip.new(data)
  let obj = deepcopy(s:Unzip)
  call obj.__init__(a:data)
  return obj
endfunction

function s:Unzip.__init__(data)
  let self.data = a:data
  let self.index = 0
endfunction

function s:Unzip.unzip()
  let entries = []
  while 1
    let entry = self.read_entry()
    if empty(entry)
      break
    endif
    call add(entries, entry)
  endwhile
  return entries
endfunction

function s:Unzip.read_entry()
  let entry = {}

  " Local file header
  let entry.signature = self.readint4()
  if entry.signature != s:LOCAL_FILE_HEADER_SIGNATURE
    call self.back(4)
    return {}
  endif
  let entry.extract = self.readint2()
  let entry.flags = self.readint2()
  let entry.method = self.readint2()
  let entry.filetime = self.readint2()
  let entry.filedate = self.readint2()
  let entry.crc32 = self.readint4()
  let entry.compressed_size = self.readint4()
  let entry.uncompressed_size = self.readint4()
  let entry.filename_length = self.readint2()
  let entry.extra_field_length = self.readint2()
  let entry.filename = bytes#bytes2str(self.read(entry.filename_length))
  let entry.extra_field = self.read(entry.extra_field_length)

  " File data
  let entry.content = self.read(entry.compressed_size)

  " Data descriptor
  if bitwise#and(entry.flags, s:FLAG_CRC32)
    let entry.crc32 = self.readint4()
    let entry.compressed_size = self.readint4()
    let entry.uncompressed_size = self.readint4()
  endif

  if entry.method == s:METHOD_NO_COMPRESSION
    " pass
  elseif entry.method == s:METHOD_DEFLATE
    let entry.content = inflate#inflate(entry.content)
  endif

  return entry
endfunction

function s:Unzip.back(size)
  let self.index -= a:size
endfunction

function s:Unzip.read(size)
  let data = self.data[self.index : self.index + a:size - 1]
  let self.index += a:size
  return data
endfunction

function s:Unzip.readint2()
  let data = self.read(2)
  return (data[1] * 0x100) + data[0]
endfunction

function s:Unzip.readint4()
  let data = self.read(4)
  return (data[3] * 0x1000000) + (data[2] * 0x10000) + (data[1] * 0x100) + data[0]
endfunction


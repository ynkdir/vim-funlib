" [Basic Tar Format]
" http://www.gnu.org/software/automake/manual/tar/Standard.html
" Last Change:  2010-10-02
" Maintainer:   Yukihiro Nakadaira <yukihiro.nakadaira@gmail.com>
" License:      This file is placed in the public domain.

function untar#untar(data)
  return s:Untar.new(a:data).untar()
endfunction

let s:REGTYPE = char2nr('0')
let s:AREGTYPE = 0
let s:LNKTYPE = char2nr('1')
let s:SYMTYPE = char2nr('2')
let s:CHRTYPE = char2nr('3')
let s:BLKTYPE = char2nr('4')
let s:DIRTYPE = char2nr('5')
let s:FIFOTYPE = char2nr('6')
let s:CONTTYPE = char2nr('7')

let s:Untar = {}

function s:Untar.new(data)
  let obj = deepcopy(s:Untar)
  call obj.__init__(a:data)
  return obj
endfunction

function s:Untar.__init__(data)
  let self.data = a:data
  let self.index = 0
endfunction

function s:Untar.untar()
  let entries = []
  let eoa = repeat([0], 1024)
  while self.data[self.index : self.index + 1024 - 1] != eoa
    let entry = self.read_entry()
    call add(entries, entry)
  endwhile
  return entries
endfunction

function s:Untar.read_entry()
  let entry = {}
  let entry.name = bytes#bytes2str(self.read(100))
  let entry.mode = str2nr(bytes#bytes2str(self.read(8)), 8)
  let entry.uid = str2nr(bytes#bytes2str(self.read(8)), 8)
  let entry.gid = str2nr(bytes#bytes2str(self.read(8)), 8)
  let entry.size = str2nr(bytes#bytes2str(self.read(12)), 8)
  let entry.mtime = self.read(12)
  let entry.chksum = self.read(8)
  let entry.typeflag = self.read(1)[0]
  let entry.linkname = self.read(100)
  let entry.magic = self.read(6)
  let entry.version = self.read(2)
  let entry.uname = self.read(32)
  let entry.gname = self.read(32)
  let entry.devmajor = self.read(8)
  let entry.devminor = self.read(8)
  let entry.prefix = self.read(155)
  let entry.content = []

  call self.skip_to_block_align()

  if entry.typeflag == s:REGTYPE || entry.typeflag == s:AREGTYPE
    let entry.content = self.read(entry.size)
    call self.skip_to_block_align()
    return entry
  elseif entry.typeflag == s:DIRTYPE
    return entry
  else
    throw printf("'%c' type is not supported", entry.typeflag)
  endif
endfunction

function s:Untar.read(size)
  let data = self.data[self.index : self.index + a:size - 1]
  let self.index += a:size
  return data
endfunction

function s:Untar.skip_to_block_align()
  if self.index % 512 != 0
    let self.index += 512 - (self.index % 512)
  endif
endfunction


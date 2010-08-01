
OBJS=hmac.o \
     sha1.o \
     sha224-256.o \
     sha384-512.o \
     shatest.o \
     usha.o

all: vimscripts

shatest: $(OBJS)
	$(CC) -o $@ $(OBJS)

.c.o:
	$(CC) -c $<

vimscripts:
	vim -u NONE -e -s -c '%s/^#include "\(.*\)"/\=readfile(submatch(1))/' \
	  -c "wq! ../autoload/hashlib/sha1.vim" sha1.vim.tpl
	vim -u NONE -e -s -c '%s/^#include "\(.*\)"/\=readfile(submatch(1))/' \
	  -c "wq! ../autoload/hashlib/sha224.vim" sha224.vim.tpl
	vim -u NONE -e -s -c '%s/^#include "\(.*\)"/\=readfile(submatch(1))/' \
	  -c "wq! ../autoload/hashlib/sha256.vim" sha256.vim.tpl
	vim -u NONE -e -s -c '%s/^#include "\(.*\)"/\=readfile(submatch(1))/' \
	  -c "wq! ../autoload/hashlib/sha384.vim" sha384.vim.tpl
	vim -u NONE -e -s -c '%s/^#include "\(.*\)"/\=readfile(submatch(1))/' \
	  -c "wq! ../autoload/hashlib/sha512.vim" sha512.vim.tpl


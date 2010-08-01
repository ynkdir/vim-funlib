
CFLAGS=-DMD=5

OBJS=md5c.o \
     mddriver.o

COMMONS=md5.h.vim

all: vimscripts

md5: md5.h $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $<

vimscripts:
	vim -u NONE -e -s -c '%s/^#include "\(.*\)"/\=readfile(submatch(1))/' \
	  -c "wq! ../autoload/hashlib/md5.vim" md5.vim.tpl


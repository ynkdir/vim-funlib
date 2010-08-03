
.PHONY: test

all: build-rfc1321 build-rfc4634

build-rfc1321:
	cd rfc1321 && $(MAKE)

build-rfc4634:
	cd rfc4634 && $(MAKE)

test: build-rfc1321 build-rfc4634
	vim -u NONE -S test/all.vim
	! grep '^\s*FAILED:' test.out

push:
	git push origin master



all: build-rfc1321 build-rfc4634

build-rfc1321:
	cd rfc1321 && $(MAKE)

build-rfc4634:
	cd rfc4634 && $(MAKE)


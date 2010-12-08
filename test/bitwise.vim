source <sfile>:p:h/test.vim
INFO bitwise test
OK bitwise#lshift(0, 0) == 0
OK bitwise#lshift(0, 1) == 0
OK bitwise#lshift(0, 31) == 0
OK bitwise#lshift(0, 32) == 0
OK bitwise#lshift(1, 0) == 0x1
OK bitwise#lshift(1, 1) == 0x2
OK bitwise#lshift(1, 31) == 0x80000000
OK bitwise#lshift(1, 32) == 0
OK bitwise#lshift(0x80000000, 0) == 0x80000000
OK bitwise#lshift(0x80000000, 1) == 0
OK bitwise#rshift(0, 0) == 0
OK bitwise#rshift(0, 1) == 0
OK bitwise#rshift(0, 31) == 0
OK bitwise#rshift(0, 32) == 0
OK bitwise#rshift(0x80000000, 0) == 0x80000000
OK bitwise#rshift(0x80000000, 1) == 0x40000000
OK bitwise#rshift(0x80000000, 31) == 0x1
OK bitwise#rshift(0x80000000, 32) == 0
OK bitwise#rshift(1, 0) == 0x1
OK bitwise#rshift(1, 1) == 0

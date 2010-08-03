source <sfile>:p:h/test.vim
INFO base64 test
OK base64#b64encode("") ==# ""
OK base64#b64encode([]) ==# ""
OK base64#b64decode("") ==# ""
OK base64#b64decode_bytes("") == []
OK base64#b64encode("hello, world") ==# "aGVsbG8sIHdvcmxk"
OK base64#b64encode("hello, worldx") ==# "aGVsbG8sIHdvcmxkeA=="
OK base64#b64encode("hello, worldxx") ==# "aGVsbG8sIHdvcmxkeHg="
OK base64#b64encode("hello, worldxxx") ==# "aGVsbG8sIHdvcmxkeHh4"
OK base64#b64decode(base64#b64encode("hello, world")) ==# "hello, world"
OK base64#b64decode(base64#b64encode("hello, worldx")) ==# "hello, worldx"
OK base64#b64decode(base64#b64encode("hello, worldxx")) ==# "hello, worldxx"
OK base64#b64decode(base64#b64encode("hello, worldxxx")) ==# "hello, worldxxx"
OK base64#b64decode_bytes(base64#b64encode("hello")) ==# [104, 101, 108, 108, 111]
EXCEPT base64#b64decode("x") => "^TypeError"

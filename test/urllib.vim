source <sfile>:p:h/test.vim
INFO urllib test
OK urllib#quote("A B C") ==# "A%20B%20C"
OK urllib#quote("A B C", " ") ==# "A B C"
OK urllib#quote("Ａ Ｂ Ｃ") ==# "%EF%BC%A1%20%EF%BC%A2%20%EF%BC%A3"
OK urllib#urlencode({"key1":"val1","key2":"val2"}) =~# 'key1=val1&key2=val2\|key2=val2&key1=val1'
OK urllib#urlencode([["key1","val1"],["key2","val2"]]) ==# "key1=val1&key2=val2"
EXCEPT urllib#urlencode("INVALID") => "^TypeError"

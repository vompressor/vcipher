# vcipher

## AES256-CBC
```
a, _ := vAES.AES_256(key.NewKeyFromString("hello", 32))
iv, _ := key.NewRandKey(a.BlockSize())
c := a.CBC(iv, vcipher.PKCS7Padding())

r, _ := c.EncryptData([]byte("hello how are you"))
r, _ = c.DecryptData(r)

t.Logf("%s", r)
```


# OpenSSL 安卓/iOS 编译过程 与 开发例程

OpenSSL 源代码：https://www.openssl.org/source/ ，这里使用 `3.0.12` LTS 版本（`1.1.1` 等低版本已经被停止支持并被官方强烈推荐停止使用）。

## 构建密钥、证书及测试签名

我们会验证一个用 OpenSSL 签名的文件。首先我们用 OpenSSL 命令行工具来构建一对 私钥/公钥，并生成一个自签名的证书，再使用私钥对一个文件签名并生成签名文件。

如果是生产环境，**私钥**一定要保管到安全稳妥的地方，不能散布出去。

```bash
# 生成私钥
openssl genpkey -algorithm RSA -out private_key.pem
# 生成公钥
openssl pkey -in private_key.pem -out public_key.pem -pubout

# 生成证书申请
openssl req -new -key private_key.pem -out cert.csr
# 生成自签名证书
openssl x509 -req -days 1024 -in cert.csr -signkey private_key.pem -out certificate.crt

# 对文件进行签名
openssl dgst -sha256 -sign private_key.pem -out signature.bin <要签名的文件>

# 验证文件签名
openssl dgst -sha256 -verify public_key.pem -signature signature.bin <要验证签名的文件>
```

这里假定我们对 `MyFile.txt` 文件进行了签名，生成了 `signature.bin` 签名文件。

后面的 Android 和 iOS/Mac 验证签名项目里用到的有（这里没有用公钥来验签，从证书里可以获取公钥）：

- 待验证文件：`MyFile.txt` 
- 签名文件：`signature.bin`
- 证书文件：`certificate.crt`



## 分平台使用

- [Android](./Android/README.md)
- [MacOS](./MacOS/README.md)
- [iOS](./iOS/README.md)
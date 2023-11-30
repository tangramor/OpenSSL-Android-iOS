### **[中文](./README_zh-CN.md)**

# OpenSSL Android/iOS Compilation Process and Development Demos

OpenSSL source code: https://www.openssl.org/source/ . Here we will use version `3.0.12` LTS (`1.1.1` and lower versions' support have been discontinued and are strongly recommended to stop using).

## Building Keys, Certificate, and Signature

We will verify a file signed with OpenSSL. First, we will use OpenSSL command-line tools to build a pair of private/public keys, generate a self-signed certificate, and use the private key to sign a file and generate a signature file.

If it is a production environment, the **private key** must be kept in a secure and safe place and should not be distributed.

```bash
# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem
# Generate public key
openssl pkey -in private_key.pem -out public_key.pem -pubout

# Generate certificate signing request
openssl req -new -key private_key.pem -out cert.csr
# Generate self-signed certificate
openssl x509 -req -days 1024 -in cert.csr -signkey private_key.pem -out certificate.crt

# Sign a file
openssl dgst -sha256 -sign private_key.pem -out signature.bin <file to sign>

# Verify file signature
openssl dgst -sha256 -verify public_key.pem -signature signature.bin <file to verify the signature of>
```

Here we assume that we have signed the `MyFile.txt` file and generated the `signature.bin` signature file.

The following Android and iOS/Mac verification projects will use:

* File to verify: `MyFile.txt`
* Signature file: `signature.bin`
* Certificate file: `certificate.crt`

## Using on Different Platforms

- [Android](./Android/README.md)
- [MacOS](./MacOS/README.md)
- [iOS](./iOS/README.md)

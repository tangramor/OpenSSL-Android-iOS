//
// Created by wangjunhua on 2023/11/29.
//

#include "Verifier.h"

bool verifyFile(AAssetManager *pAsm)
{
    AAsset *assetSign = AAssetManager_open(pAsm, "signature.bin", AASSET_MODE_UNKNOWN);
    AAsset *assetCert = AAssetManager_open(pAsm, "certificate.crt", AASSET_MODE_UNKNOWN);
    AAsset *assetFile = AAssetManager_open(pAsm, "MyFile.txt", AASSET_MODE_UNKNOWN);

    if (NULL == assetSign || NULL == assetCert || NULL == assetFile) {
        __android_log_print(ANDROID_LOG_INFO, __FUNCTION__, "failed to read file, signature or certificate assets");
        return false;
    }

    // 获取文件内容
    off_t bufferSignSize = AAsset_getLength(assetSign);
    char *bufferSign = (char *) malloc(bufferSignSize + 1);
    bufferSign[bufferSignSize] = 0;
    int numSignRead = AAsset_read(assetSign, bufferSign, bufferSignSize);

    off_t bufferCertSize = AAsset_getLength(assetCert);
    char *bufferCert = (char *) malloc(bufferCertSize + 1);
    bufferCert[bufferCertSize] = 0;
    int numCertRead = AAsset_read(assetCert, bufferCert, bufferCertSize);

    off_t bufferFileSize = AAsset_getLength(assetFile);
    char *bufferFile = (char *) malloc(bufferFileSize + 1);
    bufferFile[bufferFileSize] = 0;
    int numFileRead = AAsset_read(assetFile, bufferFile, bufferFileSize);

    X509 *certificate = loadCertificate(bufferCert);

    // Create a signature object
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX_init(mdctx);
    EVP_VerifyInit_ex(mdctx, md, NULL);

    // Initialize the signature verification, extract the public key from the certificate
    EVP_PKEY *publicKey = X509_get_pubkey(certificate);
    if (publicKey == nullptr)
    {
        std::cout << "Cannot get public key" << std::endl;
        return 1;
    }

    // PEM_write_PUBKEY(stdout, publicKey);  //print public key
    string publicKeyStr = getKeyStrFromPublickKey(publicKey);

    bool verified = verifySignature(bufferFile, publicKeyStr, bufferSign);

    return verified;
}

string getKeyStrFromPublickKey(EVP_PKEY *publicKey)
{
    // 创建一个BIO以将公钥内容输出到字符串
    string publicKeyStr;
    BIO *publicKeyBio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(publicKeyBio, publicKey) == 1)
    {
        // 将BIO中的数据读取到字符串变量中
        char *buffer;
        long publicKeySize = BIO_get_mem_data(publicKeyBio, &buffer);
        if (publicKeySize > 0)
        {
            publicKeyStr.assign(buffer, publicKeySize);
        }
    }

    // std::cout << "Publick key: \n" << publicKeyStr << std::endl;
    return publicKeyStr;
}

// Verify the sinature with File content, Public Key and Signature strings
bool verifySignature(const string &data, const string &publicKeyStr, const string &signatureStr)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 读取公钥字符串到 BIO
    BIO *publicKeyBIO = BIO_new_mem_buf(publicKeyStr.c_str(), -1);
    RSA *rsa = nullptr;

    // 从 BIO 中解析 PEM 格式的公钥
    rsa = PEM_read_bio_RSA_PUBKEY(publicKeyBIO, &rsa, nullptr, nullptr);

    // 创建 EVP_MD_CTX 对象用于验证
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);

    // 设置要验证的哈希算法 (SHA256 in this case)
    const EVP_MD *md = EVP_sha256();

    // 在 EVP_MD_CTX 对象中设置公钥
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    EVP_MD_CTX_set_pkey_ctx(md_ctx, EVP_PKEY_CTX_new(pkey, nullptr));

    // 更新签名算法的上下文，使用要验证的数据（例如文件内容）
    EVP_DigestVerifyInit(md_ctx, nullptr, md, nullptr, pkey);

    // 更新签名算法的上下文，使用要验证的数据（例如文件内容）
    EVP_DigestUpdate(md_ctx, data.c_str(), data.size());

    // 验证签名
    int result = EVP_DigestVerifyFinal(md_ctx, reinterpret_cast<const unsigned char *>(signatureStr.c_str()), signatureStr.size());

    // 释放资源
    EVP_MD_CTX_free(md_ctx);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    // 根据验证结果输出校验结果
    if (result == 1)
    {
        std::cout << "文件验证成功" << std::endl;
    }
    else
    {
        std::cout << "文件验证失败" << std::endl;
    }

    // 返回验证结果
    return (result == 1);
}

// Load Certificate content and return X509 object
X509 *loadCertificate(const string &certEntityString)
{
    BIO *bio = BIO_new(BIO_s_mem());
    string certStr = "-----BEGIN CERTIFICATE-----\n" + certEntityString + "\n-----END CERTIFICATE-----\n";
    const char *certificate = certStr.c_str();
    // std::cout << "Cert:\n" << certificate << std::endl;

    BIO_puts(bio, certificate);
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (cert == nullptr)
    {
        std::cout << "Cannot read certificate" << std::endl;
    }

    BIO_free(bio);
    return cert;
}
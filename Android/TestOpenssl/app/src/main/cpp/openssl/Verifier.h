//
// Created by wangjunhua on 2023/11/29.
//

#ifndef TESTOPENSSL_VERIFIER_H
#define TESTOPENSSL_VERIFIER_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iterator>
#include <cstring>
#include <numeric>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <android/log.h>
#include <android/asset_manager_jni.h>
#include <android/asset_manager.h>

using namespace std;

bool verifyFile(AAssetManager *pAsm);
X509 *loadCertificate(const string &certEntityString);
string getKeyStrFromPublickKey(EVP_PKEY *publicKey);
bool verifySignature(const string &data, const string &publicKeyStr, const string &signatureStr);

#endif //TESTOPENSSL_VERIFIER_H

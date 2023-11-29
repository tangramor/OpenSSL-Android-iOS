//
//  Verifier.hpp
//  TestOpenssl
//
//  Created by 王俊华 on 2023/11/28.
//

#ifndef Verifier_hpp
#define Verifier_hpp

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

using namespace std;

class Verifier
{
    public: Verifier(){};
    virtual ~Verifier(){};
    virtual bool verifyFile();
    virtual X509 *loadCertificate(const string &certEntityString);
    virtual string getKeyStrFromPublickKey(EVP_PKEY *publicKey);
    virtual bool verifySignature(const string &data, const string &publicKeyStr, const string &signatureStr);
    virtual string readFromFile(const string &filename);
};

#endif /* Verifier_hpp */

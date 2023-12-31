### **[中文](./README_zh-CN.md)**

# Android

- Android Studio: https://developer.android.com/studio
- NDK: https://github.com/android/ndk/wiki/Unsupported-Downloads ，Here we use `21e`
- OpenSSL compilation manual for Android: https://wiki.openssl.org/index.php/Android
- OpenSSL compilation script for Android: https://github.com/217heidai/openssl_for_android

## Compile OpenSSL static library

I did the following in an Ubuntu in WSL2 environment under Windows 10.

`build.sh` script：

```bash
#!/bin/bash -e

WORK_PATH=/mnt/d/workspace/openssl-3.0.12
#$(cd "$(dirname "$0")";pwd)
ANDROID_NDK_PATH=/home/tattoo/workspace/android-ndk-r21e
OPENSSL_SOURCES_PATH=${WORK_PATH}
ANDROID_TARGET_API=21
ANDROID_TARGET_ABI=$1
OUTPUT_PATH=${WORK_PATH}/openssl_3.0.12_${ANDROID_TARGET_ABI}

OPENSSL_TMP_FOLDER=/tmp/openssl_${ANDROID_TARGET_ABI}
mkdir -p ${OPENSSL_TMP_FOLDER}
cp -r ${OPENSSL_SOURCES_PATH}/* ${OPENSSL_TMP_FOLDER}

function build_library {
    mkdir -p ${OUTPUT_PATH}
    make && make install
    rm -rf ${OPENSSL_TMP_FOLDER}
    rm -rf ${OUTPUT_PATH}/bin
    rm -rf ${OUTPUT_PATH}/share
    rm -rf ${OUTPUT_PATH}/ssl
    rm -rf ${OUTPUT_PATH}/lib/engines*
    rm -rf ${OUTPUT_PATH}/lib/pkgconfig
    rm -rf ${OUTPUT_PATH}/lib/ossl-modules
    echo "Build completed! Check output libraries in ${OUTPUT_PATH}"
}

if [ "$ANDROID_TARGET_ABI" == "armeabi-v7a" ]
then
    export ANDROID_NDK_ROOT=${ANDROID_NDK_PATH}
    PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin:$PATH
    cd ${OPENSSL_TMP_FOLDER}
    ./Configure android-arm -D__ANDROID_API__=${ANDROID_TARGET_API} -static no-asm no-shared no-tests --prefix=${OUTPUT_PATH}
    build_library

elif [ "$ANDROID_TARGET_ABI" == "arm64-v8a" ]
then
    export ANDROID_NDK_ROOT=${ANDROID_NDK_PATH}
    PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin:$PATH
    cd ${OPENSSL_TMP_FOLDER}
    ./Configure android-arm64 -D__ANDROID_API__=${ANDROID_TARGET_API} -static no-asm no-shared no-tests --prefix=${OUTPUT_PATH}
    build_library

elif [ "$ANDROID_TARGET_ABI" == "x86" ]
then
    export ANDROID_NDK_ROOT=${ANDROID_NDK_PATH}
    PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin:$PATH
    cd ${OPENSSL_TMP_FOLDER}
    ./Configure android-x86 -D__ANDROID_API__=${ANDROID_TARGET_API} -static no-asm no-shared no-tests --prefix=${OUTPUT_PATH}
    build_library

elif [ "$ANDROID_TARGET_ABI" == "x86_64" ]
then
    export ANDROID_NDK_ROOT=${ANDROID_NDK_PATH}
    PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin:$PATH
    cd ${OPENSSL_TMP_FOLDER}
    ./Configure android-x86_64 -D__ANDROID_API__=${ANDROID_TARGET_API} -static no-asm no-shared no-tests --prefix=${OUTPUT_PATH}
    build_library

else
    echo "Unsupported target ABI: $ANDROID_TARGET_ABI"
    exit 1
fi
```

Put the script above to the source code folder of OpenSSL and modify the path variables (`WORK_PATH` is the path of source code，`ANDROID_NDK_PATH` is the NDK installation path),  then execute following commands to compile static libraries for 4 different architectures.

```bash
./build.sh armeabi-v7a
./build.sh arm64-v8a
./build.sh x86
./build.sh x86_64
```

The generated libraries and headers are located under `openssl_3.0.12_arm64-v8a`、`openssl_3.0.12_armeabi-v7a`、`openssl_3.0.12_x86`、`openssl_3.0.12_x86_64` in OpenSSL source code folder. Header files in `include` folders are same so we just need only one copy.

### Compile error fix

There may be following error occurs when use our compiled static libraries under  Android Studio:

```
cmd.exe /C "cd . && C:\Users\tattoo\AppData\Local\Android\Sdk\ndk\25.1.8937393\toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe --target=x86_64-none-linux-android24 --sysroot=C:/Users/tattoo/AppData/Local/Android/Sdk/ndk/25.1.8937393/toolchains/llvm/prebuilt/windows-x86_64/sysroot -fPIC -g -DANDROID -fdata-sections -ffunction-sections -funwind-tables -fstack-protector-strong -no-canonical-prefixes -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security   -fno-limit-debug-info  -static-libstdc++ -Wl,--build-id=sha1 -Wl,--no-rosegment -Wl,--fatal-warnings -Wl,--gc-sections -Wl,--no-undefined -Qunused-arguments -shared -Wl,-soname,libsignverify.so -o D:\workspace\signverify\app\build\intermediates\cxx\Debug\n6l545p2\obj\x86_64\libsignverify.so CMakeFiles/signverify.dir/signverify/Verifier.cpp.o CMakeFiles/signverify.dir/native-lib.cpp.o  D:/workspace/signverify/app/src/main/cpp/signverify/lib/x86_64/libssl.a  D:/workspace/signverify/app/src/main/cpp/signverify/lib/x86_64/libcrypto.a  -landroid  -llog  -latomic -lm && cd ."

ld: error: relocation R_X86_64_PC32 cannot be used against symbol 'bio_type_lock'; recompile with -fPIC
>>> defined in D:/workspace/signverify/app/src/main/cpp/signverify/lib/x86_64/libcrypto.a(libcrypto-lib-bio_meth.o)
>>> referenced by bio_meth.c
>>>               libcrypto-lib-bio_meth.o:(BIO_get_new_index) in archive D:/workspace/signverify/app/src/main/cpp/signverify/lib/x86_64/libcrypto.a
```

![920d4159a45b8f0fdeeefbb7494bf362.png](../images/920d4159a45b8f0fdeeefbb7494bf362.png)

This is because when compile OpenSSL, it needs each .o file to be compiled with `-fPIC` option. Here I modified `Configurations\00-base-templates.conf` to add `-fPIC` :

```perl
# -*- Mode: perl -*-
my %targets=(
    DEFAULTS => {
    template    => 1,

    cflags        => "-fPIC",
    cppflags    => "-fPIC",
    lflags        => "-fPIC",
    defines        => [],
    includes    => [],
    lib_cflags    => "-fPIC",
    lib_cppflags    => "-fPIC",
    lib_defines    => [],
    thread_scheme    => "(unknown)", # Assume we don't know
    thread_defines    => [],

    unistd        => "<unistd.h>",
    shared_target    => "-fPIC",
    shared_cflag    => "-fPIC",
    shared_defines    => [],
    shared_ldflag    => "-fPIC",
    shared_rcflag    => "",
```

## Use OpenSSL Library in Android Studio

### Create a NDK project

Opne Android Studio and create a new Native C++ project:

![4a85b36d0caf8267ad67fdc99f809ada.png](../images/4a85b36d0caf8267ad67fdc99f809ada.png)

Language choose `Java` and Build configuration language choose `Groovy DSL`:
![5ecb6c1e8e62ceae24b588f39acb7351.png](../images/5ecb6c1e8e62ceae24b588f39acb7351.png)

Other options we left using default value. And now we have a new NDK project.

Switch to **Project** view and right-click on **app -> src -> main**, create a new directory named `assets`:
![6edecf49a618636f98fc8d530b165951.png](../images/6edecf49a618636f98fc8d530b165951.png)

![48793cd4c19162acc4d8eae877413e8d.png](../images/48793cd4c19162acc4d8eae877413e8d.png)

Copy our `certificate.crt`, `signature.bin` and `MyFile.txt` to `assets`:
![e02939ebc8329105bf12ab0234d15dc2.png](../images/e02939ebc8329105bf12ab0234d15dc2.png)

Right-click on **app -> src -> main -> cpp** and create a new directory `openssl`, then copy the OpenSSL static libriaries and include folder to it:

![f434ad8f25b227a1a5f7504a19f0d310.png](../images/f434ad8f25b227a1a5f7504a19f0d310.png)

Create 2 files `Verifier.cpp` and `Verifier.h` under `openssl`:

![4ba7323b431ae2af2b5e9e564b0c6c7c.png](../images/4ba7323b431ae2af2b5e9e564b0c6c7c.png)

`Verifier.h`：

```cpp
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
```

`Verifier.cpp`：

```cpp
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

    // Get file content
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
    // Create a BIO to output public key to string
    string publicKeyStr;
    BIO *publicKeyBio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(publicKeyBio, publicKey) == 1)
    {
        // Read data in BIO to string variable
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

    // Read public key string to BIO
    BIO *publicKeyBIO = BIO_new_mem_buf(publicKeyStr.c_str(), -1);
    RSA *rsa = nullptr;

    // Read PEM public key from BIO
    rsa = PEM_read_bio_RSA_PUBKEY(publicKeyBIO, &rsa, nullptr, nullptr);

    // Create EVP_MD_CTX object for verification
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);

    // Set the hash algorithm to verify (SHA256 in this case)
    const EVP_MD *md = EVP_sha256();

    // Set public key in EVP_MD_CTX object
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    EVP_MD_CTX_set_pkey_ctx(md_ctx, EVP_PKEY_CTX_new(pkey, nullptr));

    // Initializes the context of the signature algorithm with the public key
    EVP_DigestVerifyInit(md_ctx, nullptr, md, nullptr, pkey);

    // Update the context of the signature algorithm to use the data to be verified (e.g. file contents)
    EVP_DigestUpdate(md_ctx, data.c_str(), data.size());

    // Verify the signature
    int result = EVP_DigestVerifyFinal(md_ctx, reinterpret_cast<const unsigned char *>(signatureStr.c_str()), signatureStr.size());

    // Release resources
    EVP_MD_CTX_free(md_ctx);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    // Output verification result based on the verification result
    if (result == 1)
    {
        std::cout << "File verified successfully" << std::endl;
    }
    else
    {
        std::cout << "File verify failed" << std::endl;
    }

    // Return verification result
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
```

Modify `native-lib.cpp` under **cpp** directory:

```cpp
#include <jni.h>
#include <string>
#include "openssl/Verifier.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_openssltest_sdk_testopenssl_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject thiz,
        jobject assetManager) {

    AAssetManager *pAsm = AAssetManager_fromJava(env, assetManager);
    return verifyFile(pAsm) ? env->NewStringUTF("File Verified Successfully") : env->NewStringUTF("File Verify failed");
}
```

Modify`MainActivity.java` under **java** directory:

- Add `import android.content.res.AssetManager;`
- Change `tv.setText(stringFromJNI());` to `tv.setText(stringFromJNI(this.getAssets()));`

Modify `CMakeLists.txt` under **cpp** directory, add openssl headers and static libraries, and our new source code we just added:

```CMake
cmake_minimum_required(VERSION 3.22.1)

project("testopenssl")

# OpenSSL headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/openssl/include)

# OpenSSL static libraries
add_library(local_crypto STATIC IMPORTED)
add_library(local_openssl STATIC IMPORTED)

set_target_properties(local_crypto PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/openssl/lib/${ANDROID_ABI}/libcrypto.a)
set_target_properties(local_openssl PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/openssl/lib/${ANDROID_ABI}/libssl.a)

add_library(${CMAKE_PROJECT_NAME} SHARED
        # List C/C++ source files with relative paths to this CMakeLists.txt.
        # Our source code
        openssl/Verifier.cpp
        native-lib.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}
        # List libraries link to the target library
        # Link OpenSSL static libraries
        local_openssl
        local_crypto
        android
        log)
```

Modify `build.gradle` under **app** directory. Here we need change `compileSdk` to **34** because of our Android Studio edition:

```gradle
plugins {
    id 'com.android.application'
}

android {
    namespace 'com.openssltest.sdk.testopenssl'
    compileSdk 34

    defaultConfig {
        applicationId "com.openssltest.sdk.testopenssl"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"

        testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
    }

    lintOptions {
        checkReleaseBuilds false
    }

    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
    externalNativeBuild {
        cmake {
            path file('src/main/cpp/CMakeLists.txt')
            version '3.22.1'
        }
    }
    buildFeatures {
        viewBinding true
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.10.0'
    implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
    testImplementation 'junit:junit:4.13.2'
    androidTestImplementation 'androidx.test.ext:junit:1.1.5'
    androidTestImplementation 'androidx.test.espresso:espresso-core:3.5.1'
}
```

Build and execute. It should output result like following:
![13297258ab0c417b65821a542148568e.png](../images/13297258ab0c417b65821a542148568e.png)

Modify the content of `MyFile.txt`, build and execute again, it should output `File Verify failed`.

### Generate library file

We can run `build` or `buildNeeded` task of **Gradle** and Android Studio will generate `libtestopenssl.so` library files for different architecture ( files are under `app/build/intermediates/stripped_native_libs/<release or debug>/out/lib/` directory), and we can use them in other Android projects.

![41c99ba01b4067fd778a0beb30fddf48.png](../images/41c99ba01b4067fd778a0beb30fddf48.png)

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
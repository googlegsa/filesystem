#include "Acl.h"

#include <xattr.h>

JNIEXPORT jint JNICALL Java_Acl_getxattr
  (JNIEnv *env, jobject obj, jstring path, jstring name, jobject buffer) {

   const char *nativePath = (*env)->GetStringUTFChars(env, path, 0);
   const char *nativeName = (*env)->GetStringUTFChars(env, name, 0);

   ssize_t attrlen;
   jbyte* buf = (*env)->GetDirectBufferAddress(env, buffer); 

   attrlen = getxattr(nativePath, nativeName, buf, Acl_BUFFER_SIZE);

   (*env)->ReleaseStringUTFChars(env, path, nativePath);
   (*env)->ReleaseStringUTFChars(env, name, nativeName);

   return attrlen;
}

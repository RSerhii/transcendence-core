/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest */

#ifndef _Included_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
#define _Included_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    getSenderPublicKeyReference
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_getSenderPublicKeyReference
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    getAmount
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_getAmount
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    getPKIType
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_getPKIType
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    getPKIData
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_getPKIData
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    getMemo
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_getMemo
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    getNotifyURL
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_getNotifyURL
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    getSignature
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_getSignature
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    createPaymentProtocolInvoiceRequest
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_createPaymentProtocolInvoiceRequest
(JNIEnv *, jclass, jbyteArray);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    createPaymentProtocolInvoiceRequestFull
 * Signature: (Lco/_transcendencewallet/core/BRCoreKey;JLjava/lang/String;[BLjava/lang/String;Ljava/lang/String;[B)J
 */
JNIEXPORT jlong JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_createPaymentProtocolInvoiceRequestFull
(JNIEnv *, jclass, jobject, jlong, jstring, jbyteArray, jstring, jstring, jbyteArray);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    serialize
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_serialize
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest
 * Method:    disposeNative
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolInvoiceRequest_disposeNative
(JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif

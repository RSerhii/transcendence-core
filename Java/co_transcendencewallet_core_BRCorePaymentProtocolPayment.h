/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class co_transcendencewallet_core_BRCorePaymentProtocolPayment */

#ifndef _Included_co_transcendencewallet_core_BRCorePaymentProtocolPayment
#define _Included_co_transcendencewallet_core_BRCorePaymentProtocolPayment
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolPayment
 * Method:    getMerchantData
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolPayment_getMerchantData
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolPayment
 * Method:    getTransactions
 * Signature: ()[Lco/_transcendencewallet/core/BRCoreTransaction;
 */
JNIEXPORT jobjectArray JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolPayment_getTransactions
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolPayment
 * Method:    getRefundTo
 * Signature: ()[Lco/_transcendencewallet/core/BRCoreTransactionOutput;
 */
JNIEXPORT jobjectArray JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolPayment_getRefundTo
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolPayment
 * Method:    getMerchantMemo
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolPayment_getMerchantMemo
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolPayment
 * Method:    createPaymentProtocolPayment
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolPayment_createPaymentProtocolPayment
(JNIEnv *, jclass, jbyteArray);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolPayment
 * Method:    serialize
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolPayment_serialize
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolPayment
 * Method:    disposeNative
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolPayment_disposeNative
(JNIEnv *, jobject);

/*
 * Class:     co_transcendencewallet_core_BRCorePaymentProtocolPayment
 * Method:    initializeNative
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_co_transcendencewallet_core_BRCorePaymentProtocolPayment_initializeNative
(JNIEnv *, jclass);

#ifdef __cplusplus
}
#endif
#endif

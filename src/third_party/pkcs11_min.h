/*
 * Minimal PKCS#11 (Cryptoki) subset — just the types, constants, and
 * function signatures VIRP's approve client uses. Field layouts and
 * values follow the OASIS PKCS#11 v2.40 spec (LP64). This is NOT a full
 * Cryptoki header; it exists so the approval PKCS#11 signer can build
 * without the system headers, which are absent in some environments.
 *
 * The signer resolves the C_* entry points with dlsym() rather than
 * C_GetFunctionList, so only these prototypes and constants are needed.
 * (OpenSC's opensc-pkcs11.so exports the individual C_* symbols.)
 */

#ifndef VIRP_PKCS11_MIN_H
#define VIRP_PKCS11_MIN_H

#include <stdint.h>

typedef unsigned char CK_BYTE;
typedef unsigned char CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef CK_ULONG      CK_RV;
typedef CK_ULONG      CK_SLOT_ID;
typedef CK_ULONG      CK_SESSION_HANDLE;
typedef CK_ULONG      CK_OBJECT_HANDLE;
typedef CK_ULONG      CK_FLAGS;
typedef CK_ULONG      CK_USER_TYPE;
typedef CK_ULONG      CK_MECHANISM_TYPE;
typedef CK_ULONG      CK_ATTRIBUTE_TYPE;
typedef CK_ULONG      CK_OBJECT_CLASS;
typedef CK_ULONG      CK_KEY_TYPE;
typedef void         *CK_VOID_PTR;
typedef CK_BYTE      *CK_BYTE_PTR;
typedef CK_ULONG     *CK_ULONG_PTR;
typedef void         *CK_NOTIFY;

#define CK_TRUE  1
#define CK_FALSE 0

#define CKR_OK                    0x00000000UL
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100UL

#define CKU_USER  1UL

#define CKF_SERIAL_SESSION 0x00000004UL
#define CKF_RW_SESSION     0x00000002UL

#define CKO_PUBLIC_KEY   0x00000002UL
#define CKO_PRIVATE_KEY  0x00000003UL

#define CKK_EC           0x00000003UL
#define CKK_EC_EDWARDS   0x00000040UL

#define CKA_CLASS        0x00000000UL
#define CKA_LABEL        0x00000003UL
#define CKA_KEY_TYPE     0x00000100UL
#define CKA_ID           0x00000102UL
#define CKA_EC_POINT     0x00000181UL

#define CKM_ECDSA        0x00001041UL
#define CKM_EDDSA        0x00001057UL

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR       pParameter;
    CK_ULONG          ulParameterLen;
} CK_MECHANISM;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;

/* Entry-point signatures (resolved via dlsym). */
typedef CK_RV (*CK_C_Initialize)(CK_VOID_PTR);
typedef CK_RV (*CK_C_Finalize)(CK_VOID_PTR);
typedef CK_RV (*CK_C_GetSlotList)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG_PTR);
typedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR,
                                  CK_NOTIFY, CK_SESSION_HANDLE *);
typedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE);
typedef CK_RV (*CK_C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE,
                            CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*CK_C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE *,
                                      CK_ULONG);
typedef CK_RV (*CK_C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *,
                                  CK_ULONG, CK_ULONG_PTR);
typedef CK_RV (*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE);
typedef CK_RV (*CK_C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                        CK_ATTRIBUTE *, CK_ULONG);
typedef CK_RV (*CK_C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM *,
                               CK_OBJECT_HANDLE);
typedef CK_RV (*CK_C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                           CK_BYTE_PTR, CK_ULONG_PTR);

#endif /* VIRP_PKCS11_MIN_H */

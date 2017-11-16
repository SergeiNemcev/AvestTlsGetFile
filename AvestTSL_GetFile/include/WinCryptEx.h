#ifndef _WINCRYPTEX_H_INCLUDED
#define _WINCRYPTEX_H_INCLUDED

#define CP_DEF_PROV_A "Crypto-Pro Cryptographic Service Provider"
#define CP_DEF_PROV_W L"Crypto-Pro Cryptographic Service Provider"

#ifdef UNICODE 
#define CP_DEF_PROV CP_DEF_PROV_W 
#else 
#define CP_DEF_PROV CP_DEF_PROV_A 
#endif 

#define PROV_GOST_DH 2

/* Описатели пользовательских ключей */
#define USERKEY_KEYEXCHANGE			AT_KEYEXCHANGE
#define USERKEY_SIGNATURE			AT_SIGNATURE
#define USERKEY_SIMMERYMASTERKEY		27
/* Algorithm types */
#define ALG_TYPE_GR3410				(7 << 9)
/* GR3411 sub-ids */
#define ALG_SID_GR3411				30
/* G28147 sub_ids */
#define ALG_SID_G28147				30
/* Export Key sub_id */
#define ALG_SID_PRO_EXP				31
#define ALG_SID_SIMPLE_EXP			32
/* Hash sub ids */
#define ALG_SID_GR3410				30
#define ALG_SID_G28147_MAC			31
#define ALG_SID_TLS1_MASTER_HASH		32
#define ALG_SID_TLS1_MASTER_HASH_OLD		33
/* GOST_DH sub ids */
#define ALG_SID_DH_EX_SF			30
#define ALG_SID_DH_EX_EPHEM			31
#define ALG_SID_PRO_AGREEDKEY_DH		33
#define ALG_SID_PRO_SIMMETRYKEY			34
#define ALG_SID_GR3410EL			35
#define ALG_SID_DH_EL_SF			36
#define ALG_SID_DH_EL_EPHEM			37

/* Algorithm identifier definitions */
#define CALG_GR3411 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411)

#define CALG_G28147_MAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_G28147_MAC)

#define CALG_G28147_IMIT \
    CALG_G28147_MAC

#define CALG_GR3410 \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410)

#define CALG_GR3410EL \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410EL)

#define CALG_G28147 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147)

#define CALG_DH_EX_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EX_SF)

#define CALG_DH_EX_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EX_EPHEM)

#define CALG_DH_EX \
    CALG_DH_EX_SF

#define CALG_DH_EL_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_SF)

#define CALG_DH_EL_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_EPHEM)

#define CALG_PRO_AGREEDKEY_DH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_BLOCK | ALG_SID_PRO_AGREEDKEY_DH)

#define CALG_PRO_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO_EXP)

#define CALG_SIMPLE_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP)

#define CALG_SIMMETRYKEY \
    CALG_G28147
    /* (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMMETRYKEY) */

#define CALG_TLS1_MASTER_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MASTER_HASH)

#define CALG_TLS1_MASTER_HASH_OLD \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MASTER_HASH_OLD)

#define CALG_TLS1_MAC_KEY \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY)

#define CALG_TLS1_ENC_KEY \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY)

#define CRYPT_PROMIX_MODE 0x00000001
#define CRYPT_SIMPLEMIX_MODE 0x00000000

#define CRYPT_HASH_IPAD 0x00010000
#define CRYPT_HASH_OPAD 0x00020000

/* Дополнительные параметры криптопровайдера */
#define PP_LAST_ERROR 90
#define PP_ENUMOIDS_EX 91
#define PP_HASHOID 92
#define PP_CIPHEROID 93
#define PP_SIGNATUREOID 94
#define PP_DHOID 95
#define PP_BIO_STATISTICA_LEN 97
#define PP_REBOOT 98
/*Следующий параметр используется для перехда на платформы, отличные от WIN32*/
#define PP_ANSILASTERROR 99
/* Дополнительные параметры объекта хеша */
#define HP_HASHSTARTVECT 0x0008
#define HP_HASHCOPYVAL	 0x0009
#define HP_OID 0x000a
#define HP_OPEN 0x000B

/* Дополнительные параметры ключа */
#define KP_SV KP_IV
#define KP_MIXMODE 101
#define KP_OID 102
#define KP_HASHOID 103
#define KP_CIPHEROID 104
#define KP_SIGNATUREOID 105
#define KP_DHOID 106

/* Общие коды ошибок
 * Определение кодов ошибок возвращаемые через
 * CryptGetProvParam(PP_LAST_ERROR) */
/* Коды ошибок ДСЧ */
#define GPE_FAIL_TESTBUFFER 0x0301
#define GPE_FAIL_STATBUFFER 0x0401
#define GPE_DIFERENT_PARAMETERS 0x0501
/* Коды ошибок функций ГОСТ 28147-89 */
#define GPE_CORRUPT_KEYCONTEXT 0x0102
#define	GPE_CHECKPROC_GAMMING_OFB 0x0402
#define	GPE_CHECKPROC_ENCRYPT_CFB 0x0502

/* Код ошибки контроля наличия носителя в считывателе при закрытии
 * контейнера */
#define GPE_CHECKCARRIER 0x0805
/* Коды ошибок функций подписи */
#define GPE_CORRUPT_KEYPAIR_INFO 0x0104
/* Код отказа системы тестирования */
#define GPE_CHECKPROC_TESTFAIL 0x0704

/* CRYPT_HASH_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411 "1.2.643.2.2.9"

/* CRYPT_ENCRYPT_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_28147 "1.2.643.2.2.21"

/* CRYPT_PUBKEY_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3410 "1.2.643.2.2.20"
#define szOID_CP_GOST_R3410EL "1.2.643.2.2.19"
#define szOID_CP_DH_EX "1.2.643.2.2.99"
#define szOID_CP_DH_EL "1.2.643.2.2.98"

/* CRYPT_SIGN_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411_R3410 "1.2.643.2.2.4"

/* CRYPT_ENHKEY_USAGE_OID_GROUP_ID */
#define szOID_KP_TLS_PROXY "1.2.643.2.2.34.1"

/* OID for HASH */
#define OID_HashTest "1.2.643.2.2.30.0"
#define OID_HashVerbaO "1.2.643.2.2.30.1"
#define OID_HashVar_1 "1.2.643.2.2.30.2"
#define OID_HashVar_2 "1.2.643.2.2.30.3"
#define OID_HashVar_3 "1.2.643.2.2.30.4"
#define OID_HashVar_Default OID_HashVerbaO

/* OID for Crypt */
#define OID_CryptTest "1.2.643.2.2.31.0"
#define OID_SipherVerbaO "1.2.643.2.2.31.1"
#define OID_SipherVar_1 "1.2.643.2.2.31.2" 
#define OID_SipherVar_2 "1.2.643.2.2.31.3" 
#define OID_SipherVar_3 "1.2.643.2.2.31.4" 
#define OID_SipherVar_Default OID_SipherVerbaO

#define OID_SipherSimple_VerbaO  "1.2.643.2.2.31.6"	/*VerbaO Simple*/
#define OID_SipherSimple_Var_1   "1.2.643.2.2.31.7"
#define OID_SipherSimple_Var_2   "1.2.643.2.2.31.8"
#define OID_SipherSimple_Var_3   "1.2.643.2.2.31.9"
/* OID for Signature 1024*/
#define OID_SignDH128VerbaO   "1.2.643.2.2.32.2" 	/*VerbaO*/
#define OID_Sign128Var_1   "1.2.643.2.2.32.3" 
#define OID_Sign128Var_2   "1.2.643.2.2.32.4" 
#define OID_Sign128Var_3   "1.2.643.2.2.32.5" 
/* OID for DH 1024*/
#define OID_DH128Var_1   "1.2.643.2.2.33.1" 
#define OID_DH128Var_2   "1.2.643.2.2.33.2" 
#define OID_DH128Var_3   "1.2.643.2.2.33.3" 

#define OID_ElSgDH3410 "1.2.643.2.2.36.0"

#define X509_GR3410_PARAMETERS ((LPCSTR) 5001)
#define OBJ_ASN1_CERT_28147_ENCRYPTION_PARAMETERS ((LPCSTR) 5007)

#endif /* _WINCRYPTEX_H_INCLUDED */
/* end of file: $Id: WinCryptEx.h,v 1.56 2001/08/20 15:37:15 vpopov Exp $ */

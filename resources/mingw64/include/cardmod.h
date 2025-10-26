/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */

#ifndef _INC_CARDMOD
#define _INC_CARDMOD
#include <windows.h>
#include <wincrypt.h>
#include <winscard.h>
#include <specstrings.h>
#include <bcrypt.h>

#define CARD_DATA_VALUE_UNKNOWN ((DWORD)-1)

#define CARD_RETURN_KEY_HANDLE 0x1000000

#define CARD_BUFFER_SIZE_ONLY     0x20000000
#define CARD_PADDING_INFO_PRESENT 0x40000000

#define CARD_PADDING_NONE  1
#define CARD_PADDING_PKCS1 2
#define CARD_PADDING_PSS   4
#define CARD_PADDING_OAEP  8

#define CARD_CACHE_FILE_CURRENT_VERSION                    1
#define CARD_CAPABILITIES_CURRENT_VERSION                  1
#define CONTAINER_INFO_CURRENT_VERSION                     1
#define PIN_CACHE_POLICY_CURRENT_VERSION                   6
#define PIN_INFO_CURRENT_VERSION                           6
#define PIN_INFO_REQUIRE_SECURE_ENTRY                      1
#define CARD_FILE_INFO_CURRENT_VERSION                     1
#define CARD_FREE_SPACE_INFO_CURRENT_VERSION               1
#define CARD_KEY_SIZES_CURRENT_VERSION                     1
#define CARD_RSA_KEY_DECRYPT_INFO_VERSION_ONE              1
#define CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO              2
#define CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION          CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO
#define CARD_SIGNING_INFO_BASIC_VERSION                    1
#define CARD_SIGNING_INFO_CURRENT_VERSION                  2
#define CARD_DH_AGREEMENT_INFO_VERSION                     2
#define CARD_DERIVE_KEY_VERSION                            1
#define CARD_DERIVE_KEY_VERSION_TWO                        2
#define CARD_DERIVE_KEY_CURRENT_VERSION                    CARD_DERIVE_KEY_VERSION_TWO
#define CARD_IMPORT_KEYPAIR_VERSION_SEVEN                  7
#define CARD_IMPORT_KEYPAIR_CURRENT_VERSION                CARD_IMPORT_KEYPAIR_VERSION_SEVEN
#define CARD_CHANGE_AUTHENTICATOR_VERSION_SEVEN            7
#define CARD_CHANGE_AUTHENTICATOR_CURRENT_VERSION          CARD_CHANGE_AUTHENTICATOR_VERSION_SEVEN
#define CARD_CHANGE_AUTHENTICATOR_RESPONSE_VERSION_SEVEN   7
#define CARD_CHANGE_AUTHENTICATOR_RESPONSE_CURRENT_VERSION CARD_CHANGE_AUTHENTICATOR_RESPONSE_VERSION_SEVEN
#define CARD_AUTHENTICATE_VERSION_SEVEN                    7
#define CARD_AUTHENTICATE_CURRENT_VERSION                  CARD_AUTHENTICATE_VERSION_SEVEN
#define CARD_AUTHENTICATE_RESPONSE_VERSION_SEVEN           7
#define CARD_AUTHENTICATE_RESPONSE_CURRENT_VERSION         CARD_AUTHENTICATE_RESPONSE_VERSION_SEVEN
#define CARD_DATA_VERSION_SEVEN                            7
#define CARD_DATA_VERSION_SIX                              6
#define CARD_DATA_VERSION_FIVE                             5
#define CARD_DATA_VERSION_FOUR                             4
#define CARD_DATA_CURRENT_VERSION                          CARD_DATA_VERSION_SEVEN

#define szBASE_CSP_DIR                         "mscp"
#define szINTERMEDIATE_CERTS_DIR               "mscerts"
#define szCACHE_FILE                           "cardcf"
#define szCARD_IDENTIFIER_FILE                 "cardid"
#define szCONTAINER_MAP_FILE                   "cmapfile"
#define szROOT_STORE_FILE                      "msroots"
#define szUSER_SIGNATURE_CERT_PREFIX           "ksc"
#define szUSER_KEYEXCHANGE_CERT_PREFIX         "kxc"
#define szUSER_SIGNATURE_PRIVATE_KEY_PREFIX    "kss"
#define szUSER_SIGNATURE_PUBLIC_KEY_PREFIX     "ksp"
#define szUSER_KEYEXCHANGE_PRIVATE_KEY_PREFIX  "kxs"
#define szUSER_KEYEXCHANGE_PUBLIC_KEY_PREFIX   "kxp"
#define wszCARD_USER_EVERYONE                 L"anonymous"
#define wszCARD_USER_USER                     L"user"
#define wszCARD_USER_ADMIN                    L"admin"
#define CCP_CONTAINER_INFO                    L"Container Info"
#define CCP_PIN_IDENTIFIER                    L"PIN Identifier"
#define CCP_ASSOCIATED_ECDH_KEY               L"Associated ECDH Key"
#define CP_CARD_FREE_SPACE                    L"Free Space"
#define CP_CARD_CAPABILITIES                  L"Capabilities"
#define CP_CARD_KEYSIZES                      L"Key Sizes"
#define CP_CARD_READ_ONLY                     L"Read Only Mode"
#define CP_CARD_CACHE_MODE                    L"Cache Mode"
#define CP_SUPPORTS_WIN_X509_ENROLLMENT       L"Supports Windows x.509 Enrollment"
#define CP_CARD_GUID                          L"Card Identifier"
#define CP_CARD_SERIAL_NO                     L"Card Serial Number"
#define CP_CARD_PIN_INFO                      L"PIN Information"
#define CP_CARD_LIST_PINS                     L"PIN List"
#define CP_CARD_AUTHENTICATED_STATE           L"Authenticated State"
#define CP_CARD_PIN_STRENGTH_VERIFY           L"PIN Strength Verify"
#define CP_CARD_PIN_STRENGTH_CHANGE           L"PIN Strength Change"
#define CP_CARD_PIN_STRENGTH_UNBLOCK          L"PIN Strength Unblock"
#define CP_PARENT_WINDOW                      L"Parent Window"
#define CP_PIN_CONTEXT_STRING                 L"PIN Context String"
#define CP_KEY_IMPORT_SUPPORT                 L"Key Import Support"
#define CP_ENUM_ALGORITHMS                    L"Algorithms"
#define CP_PADDING_SCHEMES                    L"Padding Schemes"
#define CP_CHAINING_MODES                     L"Chaining Modes"
#define CSF_IMPORT_KEYPAIR                    L"Import Key Pair"
#define CSF_CHANGE_AUTHENTICATOR              L"Change Authenticator"
#define CSF_AUTHENTICATE                      L"Authenticate"
#define CKP_CHAINING_MODE                     L"ChainingMode"
#define CKP_INITIALIZATION_VECTOR             L"IV"
#define CKP_BLOCK_LENGTH                      L"BlockLength"

#define MAX_CONTAINER_NAME_LEN           39
#define CARD_CREATE_CONTAINER_KEY_GEN    1
#define CARD_CREATE_CONTAINER_KEY_IMPORT 2
#define CONTAINER_MAP_VALID_CONTAINER    1
#define CONTAINER_MAP_DEFAULT_CONTAINER  2

#define AT_KEYEXCHANGE 1
#define AT_SIGNATURE   2
#define AT_ECDSA_P256  3
#define AT_ECDSA_P384  4
#define AT_ECDSA_P521  5
#define AT_ECDHE_P256  6
#define AT_ECDHE_P384  7
#define AT_ECDHE_P521  8

#define MAX_PINS                                 8
#define ROLE_EVERYONE                            0
#define ROLE_USER                                1
#define ROLE_ADMIN                               2
#define PIN_SET_NONE                             0x00
#define PIN_SET_ALL_ROLES                        0xFF
#define CREATE_PIN_SET(PinId)                    (1 << PinId)
#define SET_PIN(PinSet, PinId)                   PinSet |= CREATE_PIN_SET(PinId)
#define IS_PIN_SET(PinSet, PinId)                (0 != (PinSet & CREATE_PIN_SET(PinId)))
#define CLEAR_PIN(PinSet, PinId)                 PinSet &= ~CREATE_PIN_SET(PinId)
#define PIN_CHANGE_FLAG_UNBLOCK                  1
#define PIN_CHANGE_FLAG_CHANGEPIN                2
#define CP_CACHE_MODE_GLOBAL_CACHE               1
#define CP_CACHE_MODE_SESSION_ONLY               2
#define CP_CACHE_MODE_NO_CACHE                   3
#define CARD_AUTHENTICATE_GENERATE_SESSION_PIN   0x10000000
#define CARD_AUTHENTICATE_SESSION_PIN            0x20000000
#define CARD_PIN_STRENGTH_PLAINTEXT              1
#define CARD_PIN_STRENGTH_SESSION_PIN            2
#define CARD_PIN_SILENT_CONTEXT                  0x00000040
#define CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE 1
#define CARD_AUTHENTICATE_PIN_PIN                2

#define CARD_SECURE_KEY_INJECTION_NO_CARD_MODE 1
#define CARD_KEY_IMPORT_PLAIN_TEXT             1
#define CARD_KEY_IMPORT_RSA_KEYEST             2
#define CARD_KEY_IMPORT_ECC_KEYEST             4
#define CARD_KEY_IMPORT_SHARED_SYMMETRIC       8

#define CARD_CIPHER_OPERATION     1
#define CARD_ASYMMETRIC_OPERATION 2
#define CARD_3DES_112_ALGORITHM   BCRYPT_3DES_112_ALGORITHM
#define CARD_3DES_ALGORITHM       BCRYPT_3DES_ALGORITHM
#define CARD_AES_ALGORITHM        BCRYPT_AES_ALGORITHM
#define CARD_BLOCK_PADDING        BCRYPT_BLOCK_PADDING
#define CARD_CHAIN_MODE_CBC       BCRYPT_CHAIN_MODE_CBC

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _CARD_DIRECTORY_ACCESS_CONDITION {
  InvalidDirAc           = 0,
  UserCreateDeleteDirAc  = 1,
  AdminCreateDeleteDirAc = 2
} CARD_DIRECTORY_ACCESS_CONDITION;

typedef enum _CARD_FILE_ACCESS_CONDITION {
  InvalidAc                = 0,
  EveryoneReadUserWriteAc  = 1,
  UserWriteExecuteAc       = 2,
  EveryoneReadAdminWriteAc = 3,
  UnknownAc                = 4,
  UserReadWriteAc          = 5,
  AdminReadWriteAc         = 6
} CARD_FILE_ACCESS_CONDITION;

typedef enum {
  AlphaNumericPinType      = 0,
  ExternalPinType          = 1,
  ChallengeResponsePinType = 2,
  EmptyPinType             = 3
} SECRET_TYPE;

typedef enum {
  AuthenticationPin   = 0,
  DigitalSignaturePin = 1,
  EncryptionPin       = 2,
  NonRepudiationPin   = 3,
  AdministratorPin    = 4,
  PrimaryCardPin      = 5,
  UnblockOnlyPin      = 6
} SECRET_PURPOSE;

typedef enum {
  PinCacheNormal       = 0,
  PinCacheTimed        = 1,
  PinCacheNone         = 2,
  PinCacheAlwaysPrompt = 3
} PIN_CACHE_POLICY_TYPE;

typedef struct _CARD_CACHE_FILE_FORMAT {
  BYTE bVersion;
  BYTE bPinsFreshness;
  WORD wContainersFreshness;
  WORD wFilesFreshness;
} CARD_CACHE_FILE_FORMAT, *PCARD_CACHE_FILE_FORMAT;

typedef struct _CARD_SIGNING_INFO {
  DWORD  dwVersion;
  BYTE   bContainerIndex;
  DWORD  dwKeySpec;
  DWORD  dwSigningFlags;
  ALG_ID aiHashAlg;
  PBYTE  pbData;
  DWORD  cbData;
  PBYTE  pbSignedData;
  DWORD  cbSignedData;
  LPVOID pPaddingInfo;
  DWORD  dwPaddingType;
} CARD_SIGNING_INFO, *PCARD_SIGNING_INFO;

typedef struct _CARD_CAPABILITIES {
  DWORD   dwVersion;
  WINBOOL fCertificateCompression;
  WINBOOL fKeyGen;
} CARD_CAPABILITIES, *PCARD_CAPABILITIES;

typedef struct _CONTAINER_INFO {
  DWORD dwVersion;
  DWORD dwReserved;
  DWORD cbSigPublicKey;
  PBYTE pbSigPublicKey;
  DWORD cbKeyExPublicKey;
  PBYTE pbKeyExPublicKey;
} CONTAINER_INFO, *PCONTAINER_INFO;

typedef struct _CONTAINER_MAP_RECORD {
  WCHAR wszGuid[MAX_CONTAINER_NAME_LEN + 1];
  BYTE bFlags;
  BYTE bReserved;
  WORD wSigKeySizeBits;
  WORD wKeyExchangeKeySizeBits;
} CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;

typedef struct _CARD_RSA_DECRYPT_INFO {
  DWORD  dwVersion;
  BYTE   bContainerIndex;
  DWORD  dwKeySpec;
  PBYTE  pbData;
  DWORD  cbData;
  LPVOID pPaddingInfo;
  DWORD  dwPaddingType;
} CARD_RSA_DECRYPT_INFO, *PCARD_RSA_DECRYPT_INFO;

typedef ULONG_PTR CARD_KEY_HANDLE, *PCARD_KEY_HANDLE;

typedef struct _CARD_DERIVE_KEY {
  DWORD   dwVersion;
  DWORD   dwFlags;
  LPCWSTR pwszKDF;
  BYTE    bSecretAgreementIndex;
  PVOID   pParameterList;
  PUCHAR  pbDerivedKey;
  DWORD   cbDerivedKey;
  LPWSTR  pwszAlgId;
  DWORD   dwKeyLen;
  CARD_KEY_HANDLE hKey;
} CARD_DERIVE_KEY, *PCARD_DERIVE_KEY;

typedef struct _CARD_FILE_INFO {
  DWORD                      dwVersion;
  DWORD                      cbFileSize;
  CARD_FILE_ACCESS_CONDITION AccessCondition;
} CARD_FILE_INFO, *PCARD_FILE_INFO;

typedef struct _CARD_FREE_SPACE_INFO {
  DWORD dwVersion;
  DWORD dwBytesAvailable;
  DWORD dwKeyContainersAvailable;
  DWORD dwMaxKeyContainers;
} CARD_FREE_SPACE_INFO, *PCARD_FREE_SPACE_INFO;

typedef struct _CARD_DH_AGREEMENT_INFO {
  DWORD dwVersion;
  BYTE  bContainerIndex;
  DWORD dwFlags;
  DWORD dwPublicKey;
  PBYTE pbPublicKey;
  PBYTE pbReserved;
  DWORD cbReserved;
  BYTE  bSecretAgreementIndex;
} CARD_DH_AGREEMENT_INFO, *PCARD_DH_AGREEMENT_INFO;

typedef struct _CARD_KEY_SIZES {
  DWORD dwVersion;
  DWORD dwMinimumBitlen;
  DWORD dwDefaultBitlen;
  DWORD dwMaximumBitlen;
  DWORD dwIncrementalBitlen;
} CARD_KEY_SIZES, *PCARD_KEY_SIZES;

typedef struct _CARD_DATA CARD_DATA, *PCARD_DATA;
typedef DWORD PIN_ID, *PPIN_ID;
typedef DWORD PIN_SET, *PPIN_SET;

typedef struct _PIN_CACHE_POLICY {
  DWORD dwVersion;
  PIN_CACHE_POLICY_TYPE PinCachePolicyType;
  DWORD dwPinCachePolicyInfo;
} PIN_CACHE_POLICY, *PPIN_CACHE_POLICY;

typedef struct _PIN_INFO {
  DWORD dwVersion;
  SECRET_TYPE PinType;
  SECRET_PURPOSE PinPurpose;
  PIN_SET dwChangePermission;
  PIN_SET dwUnblockPermission;
  PIN_CACHE_POLICY PinCachePolicy;
  DWORD dwFlags;
} PIN_INFO, *PPIN_INFO;

typedef struct _CARD_ENCRYPTED_DATA {
  PBYTE pbEncryptedData;
  DWORD cbEncryptedData;
} CARD_ENCRYPTED_DATA, *PCARD_ENCRYPTED_DATA;

typedef struct _CARD_IMPORT_KEYPAIR {
  DWORD dwVersion;
  BYTE bContainerIndex;
  PIN_ID PinId;
  DWORD dwKeySpec;
  DWORD dwKeySize;
  DWORD cbInput;
  BYTE pbInput[0];
} CARD_IMPORT_KEYPAIR, *PCARD_IMPORT_KEYPAIR;

typedef struct _CARD_CHANGE_AUTHENTICATOR {
  DWORD dwVersion;
  DWORD dwFlags;
  PIN_ID dwAuthenticatingPinId;
  DWORD cbAuthenticatingPinData;
  PIN_ID dwTargetPinId;
  DWORD cbTargetData;
  DWORD cRetryCount;
  BYTE pbData[0];
} CARD_CHANGE_AUTHENTICATOR, *PCARD_CHANGE_AUTHENTICATOR;

typedef struct _CARD_CHANGE_AUTHENTICATOR_RESPONSE {
  DWORD dwVersion;
  DWORD cAttemptsRemaining;
} CARD_CHANGE_AUTHENTICATOR_RESPONSE, *PCARD_CHANGE_AUTHENTICATOR_RESPONSE;

typedef struct _CARD_AUTHENTICATE {
  DWORD dwVersion;
  DWORD dwFlags;
  PIN_ID PinId;
  DWORD cbPinData;
  BYTE pbPinData[0];
} CARD_AUTHENTICATE, *PCARD_AUTHENTICATE;

typedef struct _CARD_AUTHENTICATE_RESPONSE {
  DWORD dwVersion;
  DWORD cbSessionPin;
  DWORD cAttemptsRemaining;
  BYTE pbSessionPin[0];
} CARD_AUTHENTICATE_RESPONSE, *PCARD_AUTHENTICATE_RESPONSE;

typedef LPVOID (WINAPI *PFN_CSP_ALLOC)(SIZE_T Size);
typedef LPVOID (WINAPI *PFN_CSP_REALLOC)(LPVOID Address, SIZE_T Size);
typedef VOID (WINAPI *PFN_CSP_FREE)(LPVOID Address);

typedef DWORD (WINAPI *PFN_CSP_CACHE_ADD_FILE)(
  PVOID pvCacheContext,
  LPWSTR wszTag,
  DWORD dwFlags,
  PBYTE pbData,
  DWORD cbData
);

typedef DWORD (WINAPI *PFN_CSP_CACHE_LOOKUP_FILE)(
  PVOID pvCacheContext,
  LPWSTR wszTag,
  DWORD dwFlags,
  PBYTE *ppbData,
  PDWORD pcbData
);

typedef DWORD (WINAPI *PFN_CSP_CACHE_DELETE_FILE)(
  PVOID pvCacheContext,
  LPWSTR wszTag,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CSP_PAD_DATA)(
  PCARD_SIGNING_INFO pSigningInfo,
  DWORD cbMaxWidth,
  DWORD *pcbPaddedBuffer,
  PBYTE *ppbPaddedBuffer
);

typedef DWORD (WINAPI *PFN_CARD_ACQUIRE_CONTEXT)(
  PCARD_DATA pCardData,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_DELETE_CONTEXT)(
  PCARD_DATA pCardData
);

typedef DWORD (WINAPI *PFN_CARD_QUERY_CAPABILITIES)(
  PCARD_DATA pCardData,
  PCARD_CAPABILITIES pCardCapabilities
);

typedef DWORD (WINAPI *PFN_CARD_DELETE_CONTAINER)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwReserved
);

typedef DWORD (WINAPI *PFN_CARD_CREATE_CONTAINER)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  DWORD dwKeySpec,
  DWORD dwKeySize,
  PBYTE pbKeyData
);

typedef DWORD (WINAPI *PFN_CARD_GET_CONTAINER_INFO)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  PCONTAINER_INFO pContainerInfo
);

typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_PIN)(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbPin,
  DWORD cbPin,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_GET_CHALLENGE)(
  PCARD_DATA pCardData,
  PBYTE *ppbChallengeData,
  PDWORD pcbChallengeData
);

typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_CHALLENGE)(
  PCARD_DATA pCardData,
  PBYTE pbResponseData,
  DWORD cbResponseData,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_UNBLOCK_PIN)(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbAuthenticationData,
  DWORD cbAuthenticationData,
  PBYTE pbNewPinData,
  DWORD cbNewPinData,
  DWORD cRetryCount,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_CHANGE_AUTHENTICATOR)(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbCurrentAuthenticator,
  DWORD cbCurrentAuthenticator,
  PBYTE pbNewAuthenticator,
  DWORD cbNewAuthenticator,
  DWORD cRetryCount,
  DWORD dwFlags,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_DEAUTHENTICATE)(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_CREATE_DIRECTORY)(
  PCARD_DATA pCardData,
  LPSTR pszDirectory,
  CARD_DIRECTORY_ACCESS_CONDITION AccessCondition
);

typedef DWORD (WINAPI *PFN_CARD_DELETE_DIRECTORY)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName
);

typedef DWORD (WINAPI *PFN_CARD_CREATE_FILE)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD cbInitialCreationSize,
  CARD_FILE_ACCESS_CONDITION AccessCondition
);

typedef DWORD (WINAPI *PFN_CARD_READ_FILE)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags,
  PBYTE *ppbData,
  PDWORD pcbData
);

typedef DWORD (WINAPI *PFN_CARD_WRITE_FILE)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags,
  PBYTE pbData,
  DWORD cbData
);

typedef DWORD (WINAPI *PFN_CARD_DELETE_FILE)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_ENUM_FILES)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR *pmszFileNames,
  LPDWORD pdwcbFileName,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_FILE_INFO)(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  PCARD_FILE_INFO pCardFileInfo
);

typedef DWORD (WINAPI *PFN_CARD_QUERY_FREE_SPACE)(
  PCARD_DATA pCardData,
  DWORD dwFlags,
  PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo
);

typedef DWORD (WINAPI *PFN_CARD_QUERY_KEY_SIZES)(
  PCARD_DATA pCardData,
  DWORD dwKeySpec,
  DWORD dwFlags,
  PCARD_KEY_SIZES pKeySizes
);

typedef DWORD (WINAPI *PFN_CARD_SIGN_DATA)(
  PCARD_DATA pCardData,
  PCARD_SIGNING_INFO pInfo
);

typedef DWORD (WINAPI *PFN_CARD_RSA_DECRYPT)(
  PCARD_DATA pCardData,
  PCARD_RSA_DECRYPT_INFO pInfo
);

typedef DWORD (WINAPI *PFN_CARD_CONSTRUCT_DH_AGREEMENT)(
  PCARD_DATA pCardData,
  PCARD_DH_AGREEMENT_INFO pAgreementInfo
);

#if (_WIN32_WINNT >= 0x0600)
typedef DWORD (WINAPI *PFN_CARD_DERIVE_KEY)(
  PCARD_DATA pCardData,
  PCARD_DERIVE_KEY pAgreementInfo
);

typedef DWORD (WINAPI *PFN_CARD_DESTROY_DH_AGREEMENT)(
  PCARD_DATA pCardData,
  BYTE bSecretAgreementIndex,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CSP_GET_DH_AGREEMENT)(
  PCARD_DATA pCardData,
  PVOID hSecretAgreement,
  BYTE *pbSecretAgreementIndex,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_CHALLENGE_EX)(
  PCARD_DATA pCardData,
  PIN_ID PinId,
  PBYTE *ppbChallengeData,
  PDWORD pcbChallengeData,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_EX)(
  PCARD_DATA pCardData,
  PIN_ID PinId,
  DWORD dwFlags,
  PBYTE pbPinData,
  DWORD cbPinData,
  PBYTE *ppbSessionPin,
  PDWORD pcbSessionPin,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_CHANGE_AUTHENTICATOR_EX)(
  PCARD_DATA pCardData,
  DWORD dwFlags,
  PIN_ID dwAuthenticatingPinId,
  PBYTE pbAuthenticatingPinData,
  DWORD cbAuthenticatingPinData,
  PIN_ID dwTargetPinId,
  PBYTE pbTargetData,
  DWORD cbTargetData,
  DWORD cRetryCount,
  PDWORD pcAttemptsRemaining
);

typedef DWORD (WINAPI *PFN_CARD_DEAUTHENTICATE_EX)(
  PCARD_DATA pCardData,
  PIN_SET PinId,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_CONTAINER_PROPERTY)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_SET_CONTAINER_PROPERTY)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbDataLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_PROPERTY)(
  PCARD_DATA pCardData,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_SET_PROPERTY)(
  PCARD_DATA pCardData,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbDataLen,
  DWORD dwFlags
);
#else
typedef LPVOID PFN_CARD_DERIVE_KEY;
typedef LPVOID PFN_CARD_DESTROY_DH_AGREEMENT;
typedef LPVOID PFN_CSP_GET_DH_AGREEMENT;
typedef LPVOID PFN_CARD_GET_CHALLENGE_EX;
typedef LPVOID PFN_CARD_AUTHENTICATE_EX;
typedef LPVOID PFN_CARD_CHANGE_AUTHENTICATOR_EX;
typedef LPVOID PFN_CARD_DEAUTHENTICATE_EX;
typedef LPVOID PFN_CARD_GET_CONTAINER_PROPERTY;
typedef LPVOID PFN_CARD_SET_CONTAINER_PROPERTY;
typedef LPVOID PFN_CARD_GET_PROPERTY;
typedef LPVOID PFN_CARD_SET_PROPERTY;
#endif /*(_WIN32_WINNT >= 0x0600)*/

#if (_WIN32_WINNT >= 0x0601)
typedef DWORD (WINAPI *PFN_CSP_UNPAD_DATA)(
  PCARD_RSA_DECRYPT_INFO pRSADecryptInfo,
  DWORD *pcbUnpaddedData,
  PBYTE *ppbUnpaddedData
);

typedef DWORD (WINAPI *PFN_MD_IMPORT_SESSION_KEY)(
  PCARD_DATA pCardData,
  LPCWSTR pwszBlobType,
  LPCWSTR pwszAlgId,
  PCARD_KEY_HANDLE phKey,
  PBYTE pbInput,
  DWORD cbInput
);

typedef DWORD (WINAPI *PFN_MD_ENCRYPT_DATA)(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszSecureFunction,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags,
  PCARD_ENCRYPTED_DATA *ppEncryptedData,
  PDWORD pcEncryptedData
);

typedef DWORD (WINAPI *PFN_CARD_IMPORT_SESSION_KEY)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPVOID pPaddingInfo,
  LPCWSTR pwszBlobType,
  LPCWSTR pwszAlgId,
  PCARD_KEY_HANDLE phKey,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_SHARED_KEY_HANDLE)(
  PCARD_DATA pCardData,
  PBYTE pbInput,
  DWORD cbInput,
  PBYTE *ppbOutput,
  PDWORD pcbOutput,
  PCARD_KEY_HANDLE phKey
);

typedef DWORD (WINAPI *PFN_CARD_GET_ALGORITHM_PROPERTY)(
  PCARD_DATA pCardData,
  LPCWSTR pwszAlgId,
  LPCWSTR pwszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen, 
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_GET_KEY_PROPERTY)(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_SET_KEY_PROPERTY)(
   PCARD_DATA pCardData,
   CARD_KEY_HANDLE hKey,
   LPCWSTR pwszProperty,
   PBYTE pbInput,
   DWORD cbInput,
   DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_DESTROY_KEY)(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey
);

typedef DWORD (WINAPI *PFN_CARD_PROCESS_ENCRYPTED_DATA)(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszSecureFunction,
  PCARD_ENCRYPTED_DATA pEncryptedData,
  DWORD cEncryptedData,
  PBYTE pbOutput,
  DWORD cbOutput,
  PDWORD pdwOutputLen,
  DWORD dwFlags
);

typedef DWORD (WINAPI *PFN_CARD_CREATE_CONTAINER_EX)(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  DWORD dwKeySpec,
  DWORD dwKeySize,
  PBYTE pbKeyData,
  PIN_ID PinId
);
#else
typedef LPVOID PFN_CSP_UNPAD_DATA;
typedef LPVOID PFN_MD_IMPORT_SESSION_KEY;
typedef LPVOID PFN_MD_ENCRYPT_DATA;
typedef LPVOID PFN_CARD_IMPORT_SESSION_KEY;
typedef LPVOID PFN_CARD_GET_SHARED_KEY_HANDLE;
typedef LPVOID PFN_CARD_GET_ALGORITHM_PROPERTY;
typedef LPVOID PFN_CARD_GET_KEY_PROPERTY;
typedef LPVOID PFN_CARD_SET_KEY_PROPERTY;
typedef LPVOID PFN_CARD_DESTROY_KEY;
typedef LPVOID PFN_CARD_PROCESS_ENCRYPTED_DATA;
typedef LPVOID PFN_CARD_CREATE_CONTAINER_EX;
#endif /*(_WIN32_WINNT >= 0x0601)*/

typedef struct _CARD_DATA {
  DWORD                            dwVersion;
  PBYTE                            pbAtr;
  DWORD                            cbAtr;
  LPWSTR                           pwszCardName;
  PFN_CSP_ALLOC                    pfnCspAlloc;
  PFN_CSP_REALLOC                  pfnCspReAlloc;
  PFN_CSP_FREE                     pfnCspFree;
  PFN_CSP_CACHE_ADD_FILE           pfnCspCacheAddFile;
  PFN_CSP_CACHE_LOOKUP_FILE        pfnCspCacheLookupFile;
  PFN_CSP_CACHE_DELETE_FILE        pfnCspCacheDeleteFile;
  PVOID                            pvCacheContext;
  PFN_CSP_PAD_DATA                 pfnCspPadData;
  SCARDCONTEXT                     hSCardCtx;
  SCARDHANDLE                      hScard;
  PVOID                            pvVendorSpecific;
  PFN_CARD_DELETE_CONTEXT          pfnCardDeleteContext;
  PFN_CARD_QUERY_CAPABILITIES      pfnCardQueryCapabilities;
  PFN_CARD_DELETE_CONTAINER        pfnCardDeleteContainer;
  PFN_CARD_CREATE_CONTAINER        pfnCardCreateContainer;
  PFN_CARD_GET_CONTAINER_INFO      pfnCardGetContainerInfo;
  PFN_CARD_AUTHENTICATE_PIN        pfnCardAuthenticatePin;
  PFN_CARD_GET_CHALLENGE           pfnCardGetChallenge;
  PFN_CARD_AUTHENTICATE_CHALLENGE  pfnCardAuthenticateChallenge;
  PFN_CARD_UNBLOCK_PIN             pfnCardUnblockPin;
  PFN_CARD_CHANGE_AUTHENTICATOR    pfnCardChangeAuthenticator;
  PFN_CARD_DEAUTHENTICATE          pfnCardDeauthenticate;
  PFN_CARD_CREATE_DIRECTORY        pfnCardCreateDirectory;
  PFN_CARD_DELETE_DIRECTORY        pfnCardDeleteDirectory;
  LPVOID                           pvUnused3;
  LPVOID                           pvUnused4;
  PFN_CARD_CREATE_FILE             pfnCardCreateFile;
  PFN_CARD_READ_FILE               pfnCardReadFile;
  PFN_CARD_WRITE_FILE              pfnCardWriteFile;
  PFN_CARD_DELETE_FILE             pfnCardDeleteFile;
  PFN_CARD_ENUM_FILES              pfnCardEnumFiles;
  PFN_CARD_GET_FILE_INFO           pfnCardGetFileInfo;
  PFN_CARD_QUERY_FREE_SPACE        pfnCardQueryFreeSpace;
  PFN_CARD_QUERY_KEY_SIZES         pfnCardQueryKeySizes;
  PFN_CARD_SIGN_DATA               pfnCardSignData;
  PFN_CARD_RSA_DECRYPT             pfnCardRSADecrypt;
  PFN_CARD_CONSTRUCT_DH_AGREEMENT  pfnCardConstructDHAgreement;
  PFN_CARD_DERIVE_KEY              pfnCardDeriveKey;
  PFN_CARD_DESTROY_DH_AGREEMENT    pfnCardDestroyDHAgreement;
  PFN_CSP_GET_DH_AGREEMENT         pfnCspGetDHAgreement;
  PFN_CARD_GET_CHALLENGE_EX        pfnCardGetChallengeEx;
  PFN_CARD_AUTHENTICATE_EX         pfnCardAuthenticateEx;
  PFN_CARD_CHANGE_AUTHENTICATOR_EX pfnCardChangeAuthenticatorEx;
  PFN_CARD_DEAUTHENTICATE_EX       pfnCardDeauthenticateEx;
  PFN_CARD_GET_CONTAINER_PROPERTY  pfnCardGetContainerProperty;
  PFN_CARD_SET_CONTAINER_PROPERTY  pfnCardSetContainerProperty;
  PFN_CARD_GET_PROPERTY            pfnCardGetProperty;
  PFN_CARD_SET_PROPERTY            pfnCardSetProperty;
  PFN_CSP_UNPAD_DATA               pfnCspUnpadData;
  PFN_MD_IMPORT_SESSION_KEY        pfnMDImportSessionKey;
  PFN_MD_ENCRYPT_DATA              pfnMDEncryptData;
  PFN_CARD_IMPORT_SESSION_KEY      pfnCardImportSessionKey;
  PFN_CARD_GET_SHARED_KEY_HANDLE   pfnCardGetSharedKeyHandle;
  PFN_CARD_GET_ALGORITHM_PROPERTY  pfnCardGetAlgorithmProperty;
  PFN_CARD_GET_KEY_PROPERTY        pfnCardGetKeyProperty;
  PFN_CARD_SET_KEY_PROPERTY        pfnCardSetKeyProperty;
  PFN_CARD_DESTROY_KEY             pfnCardDestroyKey;
  PFN_CARD_PROCESS_ENCRYPTED_DATA  pfnCardProcessEncryptedData;
  PFN_CARD_CREATE_CONTAINER_EX     pfnCardCreateContainerEx;
} CARD_DATA, *PCARD_DATA;

DWORD WINAPI I_CardConvertFileNameToAnsi(
  PCARD_DATA pCardData,
  LPWSTR wszUnicodeName,
  LPSTR *ppszAnsiName
);

DWORD WINAPI CardAcquireContext(
  PCARD_DATA pCardData,
  DWORD dwFlags
);

DWORD WINAPI CardDeleteContext(
  PCARD_DATA pCardData
);

DWORD WINAPI CardQueryCapabilities(
  PCARD_DATA pCardData,
  PCARD_CAPABILITIES pCardCapabilities
);

DWORD WINAPI CardDeleteContainer(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwReserved
);

DWORD WINAPI CardCreateContainer(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  DWORD dwKeySpec,
  DWORD dwKeySize,
  PBYTE pbKeyData
);

DWORD WINAPI CardGetContainerInfo(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  PCONTAINER_INFO pContainerInfo
);

DWORD WINAPI CardAuthenticatePin(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbPin,
  DWORD cbPin,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardGetChallenge(
  PCARD_DATA pCardData,
  PBYTE *ppbChallengeData,
  PDWORD pcbChallengeData
);

DWORD WINAPI CardAuthenticateChallenge(
  PCARD_DATA pCardData,
  PBYTE pbResponseData,
  DWORD cbResponseData,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardUnblockPin(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbAuthenticationData,
  DWORD cbAuthenticationData,
  PBYTE pbNewPinData,
  DWORD cbNewPinData,
  DWORD cRetryCount,
  DWORD dwFlags
);

DWORD WINAPI CardChangeAuthenticator(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  PBYTE pbCurrentAuthenticator,
  DWORD cbCurrentAuthenticator,
  PBYTE pbNewAuthenticator,
  DWORD cbNewAuthenticator,
  DWORD cRetryCount,
  DWORD dwFlags,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardDeauthenticate(
  PCARD_DATA pCardData,
  LPWSTR pwszUserId,
  DWORD dwFlags
);

DWORD WINAPI CardCreateDirectory(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  CARD_DIRECTORY_ACCESS_CONDITION AccessCondition
);

DWORD WINAPI CardDeleteDirectory(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName
);

DWORD WINAPI CardCreateFile(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD cbInitialCreationSize,
  CARD_FILE_ACCESS_CONDITION AccessCondition
);

DWORD WINAPI CardReadFile(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags,
  PBYTE *ppbData,
  PDWORD pcbData
);

DWORD WINAPI CardWriteFile(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags,
  PBYTE pbData,
  DWORD cbData
);

DWORD WINAPI CardDeleteFile(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  DWORD dwFlags
);

DWORD WINAPI CardEnumFiles(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR *pmszFileNames,
  LPDWORD pdwcbFileName,
  DWORD dwFlags
);

DWORD WINAPI CardGetFileInfo(
  PCARD_DATA pCardData,
  LPSTR pszDirectoryName,
  LPSTR pszFileName,
  PCARD_FILE_INFO pCardFileInfo
);

DWORD WINAPI CardQueryFreeSpace(
  PCARD_DATA pCardData,
  DWORD dwFlags,
  PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo
);

DWORD WINAPI CardQueryKeySizes(
  PCARD_DATA pCardData,
  DWORD dwKeySpec,
  DWORD dwFlags,
  PCARD_KEY_SIZES pKeySizes
);

DWORD WINAPI CardSignData(
  PCARD_DATA pCardData,
  PCARD_SIGNING_INFO pInfo
);

DWORD WINAPI CardRSADecrypt(
  PCARD_DATA pCardData,
  PCARD_RSA_DECRYPT_INFO pInfo
);

DWORD WINAPI CardConstructDHAgreement(
  PCARD_DATA pCardData,
  PCARD_DH_AGREEMENT_INFO pAgreementInfo
);

DWORD WINAPI CardDeriveKey(
  PCARD_DATA pCardData,
  PCARD_DERIVE_KEY pAgreementInfo
);

DWORD WINAPI CardDestroyDHAgreement(
  PCARD_DATA pCardData,
  BYTE bSecretAgreementIndex,
  DWORD dwFlags
);

DWORD WINAPI CspGetDHAgreement(
  PCARD_DATA pCardData,
  PVOID hSecretAgreement,
  BYTE *pbSecretAgreementIndex,
  DWORD dwFlags
);

DWORD WINAPI CardGetChallengeEx(
  PCARD_DATA pCardData,
  PIN_ID PinId,
  PBYTE *ppbChallengeData,
  PDWORD pcbChallengeData,
  DWORD dwFlags
);

DWORD WINAPI CardAuthenticateEx(
  PCARD_DATA pCardData,
  PIN_ID PinId,
  DWORD dwFlags,
  PBYTE pbPinData,
  DWORD cbPinData,
  PBYTE *ppbSessionPin,
  PDWORD pcbSessionPin,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardChangeAuthenticatorEx(
  PCARD_DATA pCardData,
  DWORD dwFlags,
  PIN_ID dwAuthenticatingPinId,
  PBYTE pbAuthenticatingPinData,
  DWORD cbAuthenticatingPinData,
  PIN_ID dwTargetPinId,
  PBYTE pbTargetData,
  DWORD cbTargetData,
  DWORD cRetryCount,
  PDWORD pcAttemptsRemaining
);

DWORD WINAPI CardDeauthenticateEx(
  PCARD_DATA pCardData,
  PIN_SET PinId,
  DWORD dwFlags
);

DWORD WINAPI CardGetContainerProperty(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

DWORD WINAPI CardSetContainerProperty(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbDataLen,
  DWORD dwFlags
);

DWORD WINAPI CardGetProperty(
  PCARD_DATA pCardData,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

DWORD WINAPI CardSetProperty(
  PCARD_DATA pCardData,
  LPCWSTR wszProperty,
  PBYTE pbData,
  DWORD cbDataLen,
  DWORD dwFlags
);

DWORD WINAPI MDImportSessionKey(
  PCARD_DATA pCardData,
  LPCWSTR pwszBlobType,
  LPCWSTR pwszAlgId,
  PCARD_KEY_HANDLE phKey,
  PBYTE pbInput,
  DWORD cbInput
);

DWORD WINAPI MDEncryptData(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszSecureFunction,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags,
  PCARD_ENCRYPTED_DATA *ppEncryptedData,
  PDWORD pcEncryptedData
);

DWORD WINAPI CardImportSessionKey(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  LPVOID pPaddingInfo,
  LPCWSTR pwszBlobType,
  LPCWSTR pwszAlgId,
  PCARD_KEY_HANDLE phKey,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags
);

DWORD WINAPI CardGetSharedKeyHandle(
  PCARD_DATA pCardData,
  PBYTE pbInput,
  DWORD cbInput,
  PBYTE *ppbOutput,
  PDWORD pcbOutput,
  PCARD_KEY_HANDLE phKey
);

DWORD WINAPI CardGetAlgorithmProperty(
  PCARD_DATA pCardData,
  LPCWSTR pwszAlgId,
  LPCWSTR pwszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen, 
  DWORD dwFlags
);

DWORD WINAPI CardGetKeyProperty(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszProperty,
  PBYTE pbData,
  DWORD cbData,
  PDWORD pdwDataLen,
  DWORD dwFlags
);

DWORD WINAPI CardSetKeyProperty(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszProperty,
  PBYTE pbInput,
  DWORD cbInput,
  DWORD dwFlags
);

DWORD WINAPI CardDestroyKey(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey
);

DWORD WINAPI CardProcessEncryptedData(
  PCARD_DATA pCardData,
  CARD_KEY_HANDLE hKey,
  LPCWSTR pwszSecureFunction,
  PCARD_ENCRYPTED_DATA pEncryptedData,
  DWORD cEncryptedData,
  PBYTE pbOutput,
  DWORD cbOutput,
  PDWORD pdwOutputLen,
  DWORD dwFlags
);

DWORD WINAPI CardCreateContainerEx(
  PCARD_DATA pCardData,
  BYTE bContainerIndex,
  DWORD dwFlags,
  DWORD dwKeySpec,
  DWORD dwKeySize,
  PBYTE pbKeyData,
  PIN_ID PinId
);

#ifdef __cplusplus
}
#endif
#endif /*_INC_CARDMOD*/

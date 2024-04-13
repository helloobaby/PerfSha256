#ifndef CRYPTO_HASHER_CNG_H
#define CRYPTO_HASHER_CNG_H

#include <Windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <stdint.h>
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#pragma comment (lib,"bcrypt.lib")

#define MD5_BYTES_LN (0x10)
#define MD5_STRING_LN (0x20)
#define MD5_STRING_BUFFER_LN (0x21)

#define SHA1_BYTES_LN (0x14)
#define SHA1_STRING_LN (0x28)
#define SHA1_STRING_BUFFER_LN (0x29)

#define SHA256_BYTES_LN (0x20)
#define SHA256_STRING_LN (0x40)
#define SHA256_STRING_BUFFER_LN (0x41)


typedef struct HashCtxt {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE hash;
    NTSTATUS status;
    DWORD data_size;
    DWORD hash_size;
    DWORD hash_object_size;
    PBYTE hash_object;
}
HashCtxt, * PHashCtxt,
Md5Ctxt, * PMd5Ctxt,
Sha1Ctxt, * PSha1Ctxt,
Sha256Ctxt, * PSha256Ctxt;



NTSTATUS initSha1(
    PSha1Ctxt ctxt
);

NTSTATUS initSha256(
    PSha256Ctxt ctxt
);

NTSTATUS initMd5(
    PMd5Ctxt ctxt
);

NTSTATUS initHashCtxt(
    PHashCtxt ctxt,
    LPCWSTR AlgId
);

NTSTATUS cleanSha1(PSha1Ctxt ctxt);

NTSTATUS cleanSha256(PSha256Ctxt ctxt);

NTSTATUS cleanMd5(PMd5Ctxt ctxt);

NTSTATUS cleanHashCtxt(PHashCtxt ctxt);


/**
 * Create sha256 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   hash_bytes uint8_t* The input hash bytes
 * @param   hash_size DWORD Size of the hash_bytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256File(
    const char* path,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
);



/**
 * Create sha256 hash of a given buffer.
 *
 * @param   buffer uint8_t* the input buffer
 * @param   buffer_ln uint32_t size of buffer
 * @param   uint8_t* hash_bytes,
 * @param   hash_bytes_size DWORD Size of the hash_bytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256Buffer(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
);

/**
 * Create sha256 hash of a given buffer.
 *
 * @param   buffer uint8_t* the input buffer
 * @param   buffer_ln uint32_t size of buffer
 * @param   uint8_t* hash_bytes,
 * @param   hash_bytes_size DWORD Size of the hash_bytes.
 * @return  ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256BufferC(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size,
    PSha256Ctxt ctxt
);

/**
 * Create sha1 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   hash_bytes uint8_t* The input hash bytes
 * @param   hash_size DWORD Size of the hash_bytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1File(
    const char* path,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
);



/**
 * Create sha1 hash of a given buffer.
 *
 * @param   buffer uint8_t* the input buffer
 * @param   buffer_ln uint32_t size of buffer
 * @param   uint8_t* hash_bytes,
 * @param   hash_bytes_size DWORD Size of the hash_bytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1Buffer(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
);

/**
 * Create sha1 hash of a given buffer.
 *
 * @param   buffer uint8_t* the input buffer
 * @param   buffer_ln uint32_t size of buffer
 * @param   uint8_t* hash_bytes,
 * @param   hash_bytes_size DWORD Size of the hash_bytes.
 * @return  ctxt PSha1Ctxt initialized Sha1Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1BufferC(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size,
    PSha1Ctxt ctxt
);

/**
 * Convert hash bytes to ascii string.
 *
 * @param   hash uint8_t* The input hash bytes
 * @param   hash_size uint16_t Size of the hash_bytes.
 * @param   output char* The output hash string
 * @param   output_size uint16_t The outout buffer size. Should be at least hash_size*2 + 1.
 */
void hashToString(
    const uint8_t* hash,
    uint16_t hash_size,
    char* output,
    uint16_t output_size
);

/**
 * Print the hash to stdout.
 *
 * @param   hash uint8_t* The input hash bytes
 * @param   hash_size uint16_t Size of the hash_bytes.
 * @param   prefix char* A Prefix.
 * @param   postfix char* A Postfix.
 */
void printHash(
    const uint8_t* hash,
    uint16_t hash_size,
    const char* prefix,
    const char* postfix
);


/**
 * Create md5 hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   path char* the input file path
 * @param   hash_bytes uint8_t* The input hash bytes
 * @param   hash_size DWORD Size of the hash_bytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS md5File(
    const char* path,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
);



/**
 * Create md5 hash of a given buffer.
 *
 * @param   buffer uint8_t* the input buffer
 * @param   buffer_ln uint32_t size of buffer
 * @param   uint8_t* hash_bytes,
 * @param   hash_bytes_size DWORD Size of the hash_bytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS md5Buffer(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
);

/**
 * Create md5 hash of a given buffer.
 *
 * @param   buffer uint8_t* the input buffer
 * @param   buffer_ln uint32_t size of buffer
 * @param   uint8_t* hash_bytes,
 * @param   hash_bytes_size DWORD Size of the hash_bytes.
 * @return  ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS md5BufferC(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size,
    PMd5Ctxt ctxt
);

///**
// * Create sha256 hash of a given file.
// *
// * @param   file FILE* the input file
// * @param   output char[65] the output hash string
// * @return  NTSTATUS the success state
// */
//NTSTATUS sha256(FILE* fp, char* output);
//
///**
// * Create sha256 hash of a given string.
// *
// * @param   string char* the input string
// * @param   output char[65] the output hash string
// */
//static void sha256String(const char* string, char* output);

///**
// * Create md5 hash of a given file.
// * Using a FILE* to open the file.
// *
// * @param   path char* the input file path
// * @param   output char[33] the output hash string
// * @return  NTSTATUS the success state
// */
//NTSTATUS md5File(const char* path, char* output);
//
///**
// * Create md5 hash of a given file.
// *
// * @param   file FILE* the input file
// * @param   output char[33] the output hash string
// * @return  NTSTATUS the success state
// */
//NTSTATUS md5(FILE* fp, char* output);
//
///**
// * Create md5 hash of a given string.
// *
// * @param   string char* the input string
// * @param   output char[33] the output hash string
// */
//static void md5String(const char* string, char* output);

#endif

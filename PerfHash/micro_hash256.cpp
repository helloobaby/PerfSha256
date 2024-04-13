#pragma warning( disable : 4996 )

#include <stdio.h>
#include "micro_hash256.h"


#define BUFFER_SIZE (0x1000)



static NTSTATUS createHash(
    PHashCtxt ctxt
);

NTSTATUS hashData(
    UCHAR* buffer,
    size_t to_read,
    size_t offset,
    FILE* fp,
    PHashCtxt ctxt
)
{
    size_t bytes_read;
    int errsv;
    NTSTATUS status = 0;

    (offset);
    //fseek(fp, SEEK_SET, offset);

    errno = 0;
    bytes_read = fread(buffer, 1, to_read, fp);
    errsv = errno;
    if ((bytes_read == 0 || bytes_read != to_read) && errsv != 0)
    {
#ifdef ERROR_PRINT
        printf("ERROR (0x%x): Reading bytes failed!\n", errsv);
#endif
        status = 10;
        goto clean;
    }

    status = BCryptHashData(ctxt->hash, buffer, (ULONG)bytes_read, 0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
        status = 8;
        goto clean;
    }
clean:
    ;

    return status;
}

NTSTATUS hashBufferC(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size,
    PHashCtxt ctxt
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (hash_bytes_size < ctxt->hash_size)
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto clean;
    }

    status = createHash(ctxt);
    if (!NT_SUCCESS(status))
    {
        goto clean;
    }

    status = BCryptHashData(ctxt->hash, buffer, (ULONG)buffer_ln, 0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error 0x%x returned by BCryptHashData\n", status);
#endif
        goto clean;
    }

    // close the hash
    status = BCryptFinishHash(ctxt->hash, hash_bytes, ctxt->hash_size, 0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptFinishHash\n", status);
#endif
        goto clean;
    }

clean:
    ;

    return status;
}

NTSTATUS sha256Buffer(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
)
{
    Sha256Ctxt ctxt;
    NTSTATUS status = 0;

    status = initSha256(&ctxt);
    if (!NT_SUCCESS(status))
    {
        goto clean;
    }

    status = sha256BufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanSha256(&ctxt);

    return status;
}

NTSTATUS sha256BufferC(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size,
    PSha256Ctxt ctxt
)
{
    return hashBufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, ctxt);
}



NTSTATUS sha1Buffer(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
)
{
    Sha1Ctxt ctxt;
    NTSTATUS status = 0;

    status = initSha1(&ctxt);
    if (!NT_SUCCESS(status))
    {
        goto clean;
    }

    status = sha1BufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanSha1(&ctxt);

    return status;
}

NTSTATUS sha1BufferC(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size,
    PSha1Ctxt ctxt
)
{
    return hashBufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, ctxt);
}


NTSTATUS md5Buffer(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size
)
{
    Md5Ctxt ctxt;
    NTSTATUS status = 0;

    status = initMd5(&ctxt);
    if (!NT_SUCCESS(status))
    {
        goto clean;
    }

    status = md5BufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, &ctxt);

clean:
    cleanMd5(&ctxt);

    return status;
}

NTSTATUS md5BufferC(
    uint8_t* buffer,
    uint32_t buffer_ln,
    uint8_t* hash_bytes,
    uint16_t hash_bytes_size,
    PMd5Ctxt ctxt
)
{
    return hashBufferC(buffer, buffer_ln, hash_bytes, hash_bytes_size, ctxt);
}

void hashToString(const uint8_t* hash, uint16_t hash_size, char* output, uint16_t output_size)
{
    uint16_t i = 0;

    for (i = 0; i < hash_size; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    output[output_size - 1] = 0;
}

void printHash(const uint8_t* hash, uint16_t hash_size, const char* prefix, const char* postfix)
{
    uint16_t i = 0;

    printf("%s", prefix);
    for (i = 0; i < hash_size; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("%s", postfix);
}

NTSTATUS initSha1(PSha1Ctxt ctxt)
{
    return initHashCtxt(ctxt, BCRYPT_SHA1_ALGORITHM);
}

NTSTATUS initSha256(PSha256Ctxt ctxt)
{
    return initHashCtxt(ctxt, BCRYPT_SHA256_ALGORITHM);
}

NTSTATUS initMd5(PMd5Ctxt ctxt)
{
    return initHashCtxt(ctxt, BCRYPT_MD5_ALGORITHM);
}

NTSTATUS initHashCtxt(PHashCtxt ctxt, LPCWSTR AlgId)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE heap = GetProcessHeap();

    memset(ctxt, 0, sizeof(HashCtxt));

    //open an algorithm handle
    status = BCryptOpenAlgorithmProvider(
        &(ctxt->alg),
        AlgId,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptOpenAlgorithmProvider\n", status);
#endif
        cleanHashCtxt(ctxt);
        return -1;
    }

    //calculate the size of the buffer to hold the hash object
    status = BCryptGetProperty(
        ctxt->alg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE) & (ctxt->hash_object_size),
        sizeof(DWORD),
        &(ctxt->data_size),
        0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptGetProperty\n", status);
#endif
        cleanHashCtxt(ctxt);
        return -2;
    }

    // allocate the hash object on the heap
    ctxt->hash_object = (PBYTE)HeapAlloc(heap, 0, ctxt->hash_object_size);
    if (NULL == ctxt->hash_object)
    {
#ifdef ERROR_PRINT
        printf("ERROR: memory allocation failed\n");
#endif
        cleanHashCtxt(ctxt);
        return -3;
    }

    // calculate the length of the hash
    status = BCryptGetProperty(
        ctxt->alg,
        BCRYPT_HASH_LENGTH,
        (PBYTE) & (ctxt->hash_size),
        sizeof(DWORD),
        &(ctxt->data_size),
        0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error 0x%x returned by BCryptGetProperty\n", status);
#endif
        cleanHashCtxt(ctxt);
        return -4;
    }

    return status;
}

NTSTATUS createHash(PHashCtxt ctxt)
{
    if (ctxt->hash)
    {
        BCryptDestroyHash(ctxt->hash);
        ctxt->hash = NULL;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    status = BCryptCreateHash(
        ctxt->alg,
        &(ctxt->hash),
        ctxt->hash_object,
        ctxt->hash_object_size,
        NULL,
        0,
        0);
    if (!NT_SUCCESS(status))
    {
#ifdef ERROR_PRINT
        printf("Error (0x%x): BCryptCreateHash\n", status);
#endif
        cleanHashCtxt(ctxt);
        return 6;
    }
    return status;
}

NTSTATUS cleanSha1(PSha1Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

NTSTATUS cleanSha256(PSha256Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

NTSTATUS cleanMd5(PMd5Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

NTSTATUS cleanHashCtxt(PHashCtxt ctxt)
{
    HANDLE heap = GetProcessHeap();

    if (ctxt->alg)
    {
        BCryptCloseAlgorithmProvider(ctxt->alg, 0);
        ctxt->alg = NULL;
    }

    if (ctxt->hash)
    {
        BCryptDestroyHash(ctxt->hash);
        ctxt->hash = NULL;
    }

    if (ctxt->hash_object)
    {
        HeapFree(heap, 0, ctxt->hash_object);
        ctxt->hash_object = NULL;
    }

    return 0;
}

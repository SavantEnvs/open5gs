/*
 * Fuzz ogs_sbi_build_response() with a multipart message: the SBI multipart builder copies each
 * part body into a fixed OGS_MAX_SDU_LEN buffer.
 *
 * Input layout: byte 0 selects 1..OGS_SBI_MAX_NUM_OF_PART parts; then one little-endian u16 body
 * length per part; the remaining bytes are the fill pattern (cycled) for every part body.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../tests/fuzzing/fuzzing.h"
#include "ogs-sbi.h"

#define kMinInputLength 3

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    ogs_sbi_message_t message;
    ogs_sbi_response_t *response = NULL;
    size_t off, pat_len, i, j;
    int n;

    if (Size < kMinInputLength)
        return -1;

    n = 1 + (Data[0] % OGS_SBI_MAX_NUM_OF_PART);
    off = 1 + 2 * (size_t)n;
    if (Size < off)
        return -1;

    if (!initialized) {
        initialize();
        ogs_log_install_domain(&__ogs_sbi_domain, "sbi", OGS_LOG_NONE);
        ogs_sbi_message_init(8, 8);
    }

    memset(&message, 0, sizeof(message));
    message.ProblemDetails = OpenAPI_problem_details_create(
            NULL, ogs_strdup("multipart"), true, 400,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!message.ProblemDetails)
        return 0;

    pat_len = Size - off;

    for (i = 0; i < (size_t)n; i++) {
        size_t len = Data[1 + 2 * i] | ((size_t)Data[2 + 2 * i] << 8);
        ogs_pkbuf_t *pkbuf;
        uint8_t *dst;

        if (len == 0)
            len = 1;
        pkbuf = ogs_pkbuf_alloc(NULL, len);
        if (!pkbuf)
            break;
        dst = ogs_pkbuf_put(pkbuf, len);
        for (j = 0; j < len; j++)
            dst[j] = pat_len ? Data[off + (j % pat_len)] : 'A';

        message.part[i].content_id = "part";
        message.part[i].content_type = "application/octet-stream";
        message.part[i].pkbuf = pkbuf;
        message.num_of_part = i + 1;
    }

    response = ogs_sbi_build_response(&message, OGS_SBI_HTTP_STATUS_OK);
    if (response)
        ogs_sbi_response_free(response);

    ogs_sbi_message_free(&message);

    return 0;
}

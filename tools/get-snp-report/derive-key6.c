#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <memory.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include "snp-attestation.h"
#include "snp-ioctl6.h"
#include "helpers.h"

bool supportsDevSevGuest()
{
    return access("/dev/sev-guest", W_OK) == 0;
}

bool deriveKey6(const uint64_t *guest_field_select, void **derived_key)
{
    fprintf(stdout, "Running deriveKey6\n");
    int fd;
    int rc;

    fd = open("/dev/sev-guest", O_RDWR | O_CLOEXEC);

    if (fd < 0)
    {
        fprintf(stdout, "Failed to open /dev/sev-guest\n");
        return false;
    }
    fprintf(stdout, "Opened /dev/sev-guest\n");

    // this is the request, mostly the report data, vmpl
    snp_derived_key_req snp_request;
    // and the result from the ioctl, in the get derived_key case this will be the derived_key
    snp_derived_key_resp snp_response;

    // the object we pass to the ioctl that wraps the psp request.
    snp_guest_request_ioctl ioctl_request;

    fprintf(stdout, "Defined vars\n");

    memset(&snp_request, 0, sizeof(snp_request));
    memset(&snp_response, 0, sizeof(snp_response));
    memset(&ioctl_request, 0, sizeof(ioctl_request));

    fprintf(stdout, "Memset\n");

    memcpy(&snp_request.guest_field_select, guest_field_select, sizeof(snp_request.guest_field_select));

    fprintf(stdout, "Memcpy\n");

    ioctl_request.msg_version = 1;
    ioctl_request.req_data = (uint64_t)&snp_request;
    ioctl_request.resp_data = (uint64_t)&snp_response;

    fprintf(stdout, "Set up ptrs\n");

    rc = ioctl(fd, SNP_GET_DERIVED_KEY, &ioctl_request);

    fprintf(stdout, "Doing IOCTL\n");

    if (rc < 0)
    {
        fprintf(stdout, "Failed to issue ioctl\n");
        fprintf(stderr, "Failed to issue ioctl SEV_SNP_GET_DERIVED_KEY\n");
        return false;
    }

    fprintf(stdout, "IOCTL seems to be good\n");
    msg_derived_key_resp *response = (msg_derived_key_resp *)&snp_response.data;
    fprintf(stdout, "1\n");

    uint32_t *status = &response->status;
    fprintf(stdout, "2\n");

    if (status != 0)
    {
        fprintf(stdout, "Failed as status != 0 \n");
        fprintf(stderr, "Failed to get derived key, status: %d\n", *status);
        return false;
    };
    fprintf(stdout, "3 status good\n");

    uint8_t *_derived_key = response->derived_key;
    fprintf(stdout, "4\n");

    *derived_key = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    fprintf(stdout, "5\n");

    memcpy(*derived_key, _derived_key, sizeof(uint8_t) * 32);
    fprintf(stdout, "6 done, now printing\n");

    // Print the key (for testing right now)
    for (int i = 0; i < 32; i++)
    {
        printf("%u ", response->derived_key[i]);
    }

    return true;
}

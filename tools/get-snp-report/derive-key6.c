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

bool deriveKey6(const uint64_t *guest_field_select, uint8_t derived_key[32])
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

    // this is the request
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

    // snp_request.guest_field_select = *guest_field_select;
    memcpy(&snp_request.guest_field_select, guest_field_select, sizeof(snp_request.guest_field_select));

    fprintf(stdout, "Memcpy\n");

    // Offset Bits Name Description
    // 0h 31:3 - Reserved. Must be zero.
    // 2:1 KEY_SEL Selects which key to use for derivation.
    // 0: If VLEK is installed, derive with VLEK. Otherwise, derive
    // with VCEK.
    // 1: Derive with VCEK.
    // 2: Derive with VLEK.
    // 3: Reserved.
    // Present when the Vlek feature bit is set.
    // 0 ROOT_KEY_SELECT Selects the root key from which to derive the key. 0
    // indicates VCEK. 1 indicates VMRK.
    // 4h 31:0 - Reserved. Must be zero.
    //
    // ^^^ all set to 0 which is fine

// 8h 63:0 GUEST_FIELD_SELECT Bitmask indicating which data will be mixed into the
// derived key. See Table 17 for the structure of this bitmask.

// 10h 31:0 VMPL The VMPL to mix into the derived key. Must be greater
// than or equal to the current VMPL.

// 14h 31:0 GUEST_SVN The guest SVN to mix into the key. Must not exceed the
// guest SVN provided at launch in the ID block. SHOULD BE FINE AS 0
// 18h 63:0 TCB_VERSION The TCB version to mix into the derived key. Must not
// exceed CommittedTcb. SHOULD BE FINE AS 0


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

fprintf(stdout, "2\n");

if (response->status != 0)
{
    fprintf(stdout, "Failed as status != 0 \n");
    fprintf(stderr, "Failed to get derived key, status: %d\n", response->status);
    return false;
};
fprintf(stdout, "3 status good\n");

fprintf(stdout, "4\n");


// Print the key (for testing right now)
for (size_t i = 0; i < 32; i++)
{
    derived_key[i] = response->derived_key[i];
    printf("%02x", response->derived_key[i]);
}
printf("\n");

return true;
}

#include "pch.h"

#pragma comment(lib, "ntdll")

// clang-format off
/*

Status code                                     Meaning
-- WARNING --
STATUS_BUFFER_OVERFLOW          0x80000005      The output buffer was filled before all of the EA data could be returned. Only complete FILE_FULL_EA_INFORMATION structures are returned.
STATUS_NO_MORE_EAS              0x80000012      No more extended attributes (EAs) were found for the file.
STATUS_INVALID_EA_NAME          0x80000013      The specified extended attribute (EA) name contains at least one illegal character.
                                                An array of 8-bit ASCII characters that contains the extended attribute name followed by a single terminating null character byte.
                                                The EaName MUST be less than 255 characters and MUST NOT contain any of the following characters:
                                                ASCII values 0x00 - 0x1F, \ / : * ? " < > | , + = [ ] ;
STATUS_EA_LIST_INCONSISTENT     0x80000014      The extended attribute (EA) list is inconsistent.
STATUS_INVALID_EA_FLAG          0x80000015      An invalid extended attribute (EA) flag was set.

-- ERROR --
STATUS_INVALID_DEVICE_REQUEST   0xC0000010      The specified request is not a valid operation for the target device.
STATUS_ACCESS_DENIED            0xC0000022      A process has requested access to an object, but has not been granted those access rights.
STATUS_BUFFER_TOO_SMALL         0xC0000023      The buffer is too small to contain the entry. No information has been written to the buffer.
STATUS_EAS_NOT_SUPPORTED        0xC000004F      An operation involving EAs failed because the file system does not support EAs.
STATUS_EA_TOO_LARGE             0xC0000050      An EA operation failed because EA set is too large.
STATUS_NONEXISTENT_EA_ENTRY     0xC0000051      An EA operation failed because the name or EA index is invalid.
STATUS_NO_EAS_ON_FILE           0xC0000052      The file for which EAs were requested has no EAs.
STATUS_EA_CORRUPT_ERROR         0xC0000053      The EA is corrupt and non-readable.
STATUS_INSUFFICIENT_RESOURCES   0xC000009A      Insufficient system resources exist to complete the API.

*/
// clang-format on

int wmain(int argc, const wchar_t* argv[])
{
    return 0;
}


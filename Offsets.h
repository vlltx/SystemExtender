#pragma once
#include "Kse.h"

#define RVA(p, o) ((PUINT8)p + o)

extern UINT64 EprocessSeAuditProcessCreateInfoOffset;
extern UINT64 EprocessProtectionOffset;
extern UINT64 EprocessMitigationFlagsOffset;
extern UINT64 EprocessSignatureLevelOffset;
extern UINT64 EprocessMitigationFlags2Offset;
extern UINT64 EprocessMitigationFlags3Offset;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);
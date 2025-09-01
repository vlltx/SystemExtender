#pragma once
#include <ntifs.h>
#include "Offsets.h"

// To keep things simple all method definitions will be put here

NTSTATUS KseDispatchCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);

NTSTATUS KseDispatchDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
);

PVOID RtlFindPattern(
  _In_ PVOID Source,
  _In_ SIZE_T
  _In_ SourceLength,
  _In_ PVOID Pattern,
  _In_ SIZE_T PatternLength
);

#define CTL_SET_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_GET_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_SET_MITIGATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_GET_MITIGATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_OPEN_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_OPEN_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)

typedef struct _KSE_OPEN_OBJECT {
	CLIENT_ID ClientId;
	HANDLE ObjectHandle;
} KSE_OPEN_OBJECT, * PKSE_OPEN_OBJECT;

typedef struct _KSE_SET_PROTECTION {
	HANDLE ProcessId;
	UCHAR Protection;
} KSE_SET_PROTECTION, * PKSE_SET_PROTECTION;

typedef struct _KSE_SET_MITIGATION {
	HANDLE ProcessId;
	union
	{
		ULONG MitigationFlags;                                              //0x750
		struct
		{
			ULONG ControlFlowGuardEnabled : 1;                                //0x750
			ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x750
			ULONG ControlFlowGuardStrict : 1;                                 //0x750
			ULONG DisallowStrippedImages : 1;                                 //0x750
			ULONG ForceRelocateImages : 1;                                    //0x750
			ULONG HighEntropyASLREnabled : 1;                                 //0x750
			ULONG StackRandomizationDisabled : 1;                             //0x750
			ULONG ExtensionPointDisable : 1;                                  //0x750
			ULONG DisableDynamicCode : 1;                                     //0x750
			ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x750
			ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x750
			ULONG AuditDisableDynamicCode : 1;                                //0x750
			ULONG DisallowWin32kSystemCalls : 1;                              //0x750
			ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x750
			ULONG EnableFilteredWin32kAPIs : 1;                               //0x750
			ULONG AuditFilteredWin32kAPIs : 1;                                //0x750
			ULONG DisableNonSystemFonts : 1;                                  //0x750
			ULONG AuditNonSystemFontLoading : 1;                              //0x750
			ULONG PreferSystem32Images : 1;                                   //0x750
			ULONG ProhibitRemoteImageMap : 1;                                 //0x750
			ULONG AuditProhibitRemoteImageMap : 1;                            //0x750
			ULONG ProhibitLowILImageMap : 1;                                  //0x750
			ULONG AuditProhibitLowILImageMap : 1;                             //0x750
			ULONG SignatureMitigationOptIn : 1;                               //0x750
			ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x750
			ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x750
			ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x750
			ULONG AuditLoaderIntegrityContinuity : 1;                         //0x750
			ULONG EnableModuleTamperingProtection : 1;                        //0x750
			ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x750
			ULONG RestrictIndirectBranchPrediction : 1;                       //0x750
			ULONG IsolateSecurityDomain : 1;                                  //0x750
		} MitigationFlagsValues;                                            //0x750
	} u1;
	union
	{
		ULONG MitigationFlags2;                                             //0x754
		struct
		{
			ULONG EnableExportAddressFilter : 1;                              //0x754
			ULONG AuditExportAddressFilter : 1;                               //0x754
			ULONG EnableExportAddressFilterPlus : 1;                          //0x754
			ULONG AuditExportAddressFilterPlus : 1;                           //0x754
			ULONG EnableRopStackPivot : 1;                                    //0x754
			ULONG AuditRopStackPivot : 1;                                     //0x754
			ULONG EnableRopCallerCheck : 1;                                   //0x754
			ULONG AuditRopCallerCheck : 1;                                    //0x754
			ULONG EnableRopSimExec : 1;                                       //0x754
			ULONG AuditRopSimExec : 1;                                        //0x754
			ULONG EnableImportAddressFilter : 1;                              //0x754
			ULONG AuditImportAddressFilter : 1;                               //0x754
			ULONG DisablePageCombine : 1;                                     //0x754
			ULONG SpeculativeStoreBypassDisable : 1;                          //0x754
			ULONG CetUserShadowStacks : 1;                                    //0x754
			ULONG AuditCetUserShadowStacks : 1;                               //0x754
			ULONG AuditCetUserShadowStacksLogged : 1;                         //0x754
			ULONG UserCetSetContextIpValidation : 1;                          //0x754
			ULONG AuditUserCetSetContextIpValidation : 1;                     //0x754
			ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x754
			ULONG CetUserShadowStacksStrictMode : 1;                          //0x754
			ULONG BlockNonCetBinaries : 1;                                    //0x754
			ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x754
			ULONG AuditBlockNonCetBinaries : 1;                               //0x754
			ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x754
			ULONG XtendedControlFlowGuard_Deprecated : 1;                     //0x754
			ULONG AuditXtendedControlFlowGuard_Deprecated : 1;                //0x754
			ULONG PointerAuthUserIp : 1;                                      //0x754
			ULONG AuditPointerAuthUserIp : 1;                                 //0x754
			ULONG AuditPointerAuthUserIpLogged : 1;                           //0x754
			ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x754
			ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x754
		} MitigationFlags2Values;                                           //0x754
	} u2;
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
} KSE_SET_MITIGATION, * PKSE_SET_MITIGATION;


#pragma pack(pop)

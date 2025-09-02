#include "Kse.h"

DRIVER_INITIALIZE KseDriverEntry;
DRIVER_UNLOAD KseDriverUnload;

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KSystemExtender");
UNICODE_STRING DeviceLinkName = RTL_CONSTANT_STRING(L"\\??\\KSystemExtenderL");

UINT64 EprocessSeAuditProcessCreateInfoOffset;
UINT64 EprocessProtectionOffset;
UINT64 EprocessMitigationFlagsOffset;
UINT64 EprocessMitigationFlags2Offset;
UINT64 EprocessMitigationFlags3Offset;
UINT64 EprocessSignatureLevelOffset;

BOOLEAN KseInitializeOffsets()
{
	RTL_OSVERSIONINFOW VersionInfo;
	RtlGetVersion(&VersionInfo);

	switch (VersionInfo.dwBuildNumber) {
	case 26100:
	{
		EprocessSeAuditProcessCreateInfoOffset = 0x350;
		EprocessProtectionOffset = 0x5fa;
		EprocessMitigationFlagsOffset = 0x750;
		EprocessMitigationFlags2Offset = 0x754;
		EprocessMitigationFlags3Offset = 0x7d8;
		EprocessSignatureLevelOffset = 0x5f8;
		break;
	}
	default:
	{
		return FALSE;
	}
	}

	return TRUE;
}

NTSTATUS KseDriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS Status;

	if (!KseInitializeOffsets()) {
		return STATUS_TOO_LATE;
	}

	DriverObject->DriverUnload = KseDriverUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = KseDispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KseDispatchDeviceControl;

	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = IoCreateSymbolicLink(&DeviceLinkName, &DeviceName);
	if (!NT_SUCCESS(Status))
		return Status;

	return STATUS_SUCCESS;
}

VOID KseDriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&DeviceLinkName);
}
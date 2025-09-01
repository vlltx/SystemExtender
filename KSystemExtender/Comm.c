#include "Kse.h"

UNICODE_STRING SystemInformerName = RTL_CONSTANT_STRING(L"SystemInformer.exe");

NTSTATUS KseDispatchCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;

	PEPROCESS Requestor = IoGetRequestorProcess(Irp);

	PUNICODE_STRING* ProcessName = (PUNICODE_STRING*)RVA(Requestor, EprocessSeAuditProcessCreateInfoOffset);
	if (RtlFindPattern((*ProcessName)->Buffer, (*ProcessName)->MaximumLength, SystemInformerName.Buffer, SystemInformerName.Length) == SystemInformerName.Length) {
		Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		return STATUS_ACCESS_DENIED;
	}

	IoCompleteRequest(Irp, 0);

	return Irp->IoStatus.Status;
}

NTSTATUS KseDispatchDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS Status = STATUS_SUCCESS;

	PEPROCESS Process;
	PKSE_SET_PROTECTION SetProtectionArgs;
	PKSE_SET_MITIGATION SetMitigationArgs;
	PKSE_OPEN_OBJECT OpenObjectArgs;

	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (StackLocation->Parameters.DeviceIoControl.IoControlCode) {
	case CTL_SET_PROTECTION:
	{
		SetProtectionArgs = Irp->AssociatedIrp.SystemBuffer;

		Status = PsLookupProcessByProcessId(SetProtectionArgs->ProcessId, &Process);
		if (!NT_SUCCESS(Status))
			goto end;

		PUCHAR Protection = RVA(Process, EprocessProtectionOffset);
		*Protection = SetProtectionArgs->Protection;

		break;
	}
	case CTL_GET_PROTECTION:
	{
		SetProtectionArgs = Irp->AssociatedIrp.SystemBuffer;

		Status = PsLookupProcessByProcessId(SetProtectionArgs->ProcessId, &Process);
		if (!NT_SUCCESS(Status))
			goto end;

		PUCHAR Protection = RVA(Process, EprocessProtectionOffset);
		SetProtectionArgs->Protection = *Protection;
		Irp->IoStatus.Information = sizeof(KSE_SET_PROTECTION);

		break;
	}
	case CTL_SET_MITIGATION:
	{
		SetMitigationArgs = Irp->AssociatedIrp.SystemBuffer;

		Status = PsLookupProcessByProcessId(SetMitigationArgs->ProcessId, &Process);
		if (!NT_SUCCESS(Status))
			goto end;

		PUINT8 Mitigation = RVA(Process, EprocessMitigationFlagsOffset);
		RtlCopyMemory(Mitigation, RVA(SetMitigationArgs, 8), 8);

		*(PUCHAR)(RVA(Process, EprocessSignatureLevelOffset)) = SetMitigationArgs->SignatureLevel;
		*(PUCHAR)(RVA(Process, EprocessSignatureLevelOffset + 1)) = SetMitigationArgs->SectionSignatureLevel;

		break;
	}
	case CTL_GET_MITIGATION:
	{
		SetMitigationArgs = Irp->AssociatedIrp.SystemBuffer;

		Status = PsLookupProcessByProcessId(SetMitigationArgs->ProcessId, &Process);
		if (!NT_SUCCESS(Status))
			goto end;

		PUINT8 Mitigation = RVA(Process, EprocessMitigationFlagsOffset);
		SetMitigationArgs->u1.MitigationFlags = *(PUINT32)Mitigation;
		SetMitigationArgs->u2.MitigationFlags2 = *((PUINT32)Mitigation + 1);

		SetMitigationArgs->SignatureLevel = *(PUCHAR)(RVA(Process, EprocessSignatureLevelOffset));
		SetMitigationArgs->SectionSignatureLevel = *(PUCHAR)(RVA(Process, EprocessSignatureLevelOffset + 1));

		Irp->IoStatus.Information = sizeof(KSE_SET_MITIGATION);

		break;
	}
	case CTL_OPEN_PROCESS:
	{
		OpenObjectArgs = Irp->AssociatedIrp.SystemBuffer;

		OBJECT_ATTRIBUTES Attributes;
		InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);

		Status = ZwOpenProcess(&OpenObjectArgs->ObjectHandle, PROCESS_ALL_ACCESS, &Attributes, &OpenObjectArgs->ClientId);
		Irp->IoStatus.Information = sizeof(KSE_OPEN_OBJECT);

		break;
	}
	case CTL_OPEN_THREAD:
	{
		OpenObjectArgs = Irp->AssociatedIrp.SystemBuffer;

		OBJECT_ATTRIBUTES Attributes;
		InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);

		Status = ZwOpenThread(&OpenObjectArgs->ObjectHandle, PROCESS_ALL_ACCESS, &Attributes, &OpenObjectArgs->ClientId);
		Irp->IoStatus.Information = sizeof(KSE_OPEN_OBJECT);

		break;
	}
	}

end:
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, 0);
	return Status;

}

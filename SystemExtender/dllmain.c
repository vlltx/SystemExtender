#include "plugin.h"

PPH_PLUGIN PluginInstance;
PH_CALLBACK_REGISTRATION PluginLoadCallbackRegistration;
PH_CALLBACK_REGISTRATION ProcessPropertiesInitializingCallbackRegistration;
HANDLE ExtenderHandle = NULL;

NtOpenProcessType NtOpenProcessOriginal;
NtOpenProcessType NtOpenThreadOriginal;

NTSTATUS NTAPI ExNtOpenThread(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
)
{
    if (PhGetIntegerSetting(SETTING_NAME_ALWAYS_USE_KERNEL_HANDLES) == 0 || ExtenderHandle == NULL || ClientId == NULL)
        return NtOpenThreadOriginal(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    IO_STATUS_BLOCK statusBlock;
    KSE_OPEN_OBJECT command = { 0 };
    KSE_OPEN_OBJECT recv = { 0 };

    command.ClientId = *ClientId;

    NTSTATUS status = NtDeviceIoControlFile(ExtenderHandle, NULL, NULL, NULL, &statusBlock, CTL_OPEN_THREAD, &command, sizeof(command), &recv, sizeof(recv));
    if (!NT_SUCCESS(status)) return status;

    *ProcessHandle = recv.ObjectHandle;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ExNtOpenProcess(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
)
{
    if (PhGetIntegerSetting(SETTING_NAME_ALWAYS_USE_KERNEL_HANDLES) == 0 || ExtenderHandle == NULL || ClientId == NULL)
        return NtOpenProcessOriginal(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);

    IO_STATUS_BLOCK statusBlock;
    KSE_OPEN_OBJECT command = { 0 };
    KSE_OPEN_OBJECT recv = { 0 };

    command.ClientId = *ClientId;

    NTSTATUS status = NtDeviceIoControlFile(ExtenderHandle, NULL, NULL, NULL, &statusBlock, CTL_OPEN_PROCESS, &command, sizeof(command), &recv, sizeof(recv));
    if (!NT_SUCCESS(status)) return status;

    *ThreadHandle = recv.ObjectHandle;

    return STATUS_SUCCESS;
}

_Function_class_(PH_CALLBACK_FUNCTION)
VOID NTAPI LoadCallback(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    ExtenderHandle = CreateFileW(L"\\\\.\\KSystemExtenderL", FILE_READ_DATA | FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (ExtenderHandle == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "Could not open SystemExtender driver.", "SystemExtender", MB_ICONERROR);
        return;
    }

    if (MH_Initialize() != MH_OK) {
        MessageBoxA(NULL, "Cannot initialize MinHook!", "SystemExtender", MB_ICONERROR);
        CloseHandle(ExtenderHandle);
        return;
    }

    if (!(MH_CreateHook(&NtOpenProcess, &ExNtOpenProcess, &NtOpenProcessOriginal) == MH_OK && MH_EnableHook(&NtOpenProcess) == MH_OK)) {
        MessageBoxA(NULL, "Cannot hook NtOpenProcess!", "SystemExtender", MB_ICONERROR);
        CloseHandle(ExtenderHandle);
        return;
    }

    if (!(MH_CreateHook(&NtOpenThread, &ExNtOpenThread, &NtOpenThreadOriginal) == MH_OK && MH_EnableHook(&NtOpenThread) == MH_OK)) {
        MessageBoxA(NULL, "Cannot hook NtOpenThread!", "SystemExtender", MB_ICONERROR);
        CloseHandle(ExtenderHandle);
        return;
    }
}

_Function_class_(PH_CALLBACK_FUNCTION)
VOID NTAPI UnloadCallback(
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID Context
)
{
    CloseHandle(ExtenderHandle);
}

_Function_class_(PH_CALLBACK_FUNCTION)
VOID ProcessPropertiesInitializingCallback(
    _In_ PVOID Parameter,
    _In_ PVOID Context
)
{
    PPH_PLUGIN_PROCESS_PROPCONTEXT propContext = Parameter;

    PhAddProcessPropPage(
        propContext->PropContext,
        PhCreateProcessPropPageContextEx(PluginInstance->DllBase, MAKEINTRESOURCE(101), ProcessExtendedPageProc, NULL)
    );
}

LOGICAL DllMain(
    _In_ HINSTANCE Instance,
    _In_ ULONG Reason,
    _Reserved_ PVOID Reserved
)
{
    if (Reason == DLL_PROCESS_ATTACH) {
        PPH_PLUGIN_INFORMATION info;
        PH_SETTING_CREATE settings[] = {
            {IntegerSettingType, SETTING_NAME_ALWAYS_USE_KERNEL_HANDLES, L"1"},
        };

        PluginInstance = PhRegisterPlugin(PLUGIN_NAME, Instance, &info);
        if (PluginInstance == NULL)
            return FALSE;

        PhAddSettings(settings, RTL_NUMBER_OF(settings));

        info->DisplayName = L"System Extender";
        info->Author = L"vlltx";
        info->Url = L"https://github.com/vlltx/SystemExtender";
        info->Description = L"Uses System Extender kernel module to enhance System Informer's abilities.";

        PhRegisterCallback(PhGetPluginCallback(PluginInstance, PluginCallbackLoad), LoadCallback, NULL, &PluginLoadCallbackRegistration);
        PhRegisterCallback(PhGetGeneralCallback(GeneralCallbackProcessPropertiesInitializing), ProcessPropertiesInitializingCallback, NULL, &ProcessPropertiesInitializingCallbackRegistration);
    }
    return TRUE;
}


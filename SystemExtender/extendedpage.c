#include "plugin.h"
#include "resource.h"

HANDLE protectionBox;
HANDLE signerBox;
HANDLE signatureLevelBox;
HANDLE sectionSignatureLevelBox;
HANDLE controlFlowGuardCheck;
HANDLE controlFlowGuardStrictCheck;
HANDLE controlFlowGuardExportSupressionCheck;
HANDLE disallowStrippedImagesCheck;
HANDLE forceRelocateImagesCheck;
HANDLE highEntropyAslrCheck;
HANDLE cetUserShadowStacksStrictCheck;
HANDLE extensionPointDisableCheck;
HANDLE disableDynamicCodeCheck;
HANDLE disallowWin32kSyscallsCheck;
HANDLE filterWin32kSyscallsCheck;
HANDLE disableNonSystemFontsCheck;
HANDLE moduleTamperingProtectionCheck;
HANDLE isolateSecurityDomainCheck;
HANDLE cetUserShadowStacksCheck;

INT_PTR CALLBACK ProcessExtendedPageProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    LPPROPSHEETPAGE propSheetPage;
    PPH_PROCESS_PROPPAGECONTEXT propPageContext;
    PPH_PROCESS_ITEM processItem;
    
    if (!PhPropPageDlgProcHeader(hwndDlg, uMsg, lParam, &propSheetPage, &propPageContext, &processItem))
        return FALSE;

    if (ExtenderHandle == NULL)
        return FALSE;

    switch (uMsg) {
    case WM_INITDIALOG: {
         protectionBox = GetDlgItem(hwndDlg, IDC_COMBO1);
         signerBox = GetDlgItem(hwndDlg, IDC_COMBO2);
         signatureLevelBox = GetDlgItem(hwndDlg, 1022);
         sectionSignatureLevelBox = GetDlgItem(hwndDlg, 1023);
         controlFlowGuardCheck = GetDlgItem(hwndDlg, IDC_CHECK1);
         controlFlowGuardStrictCheck = GetDlgItem(hwndDlg, IDC_CHECK2);
         controlFlowGuardExportSupressionCheck = GetDlgItem(hwndDlg, IDC_CHECK3);
         disallowStrippedImagesCheck = GetDlgItem(hwndDlg, IDC_CHECK4);
         forceRelocateImagesCheck = GetDlgItem(hwndDlg, IDC_CHECK5);
         highEntropyAslrCheck = GetDlgItem(hwndDlg, IDC_CHECK6);
         cetUserShadowStacksStrictCheck = GetDlgItem(hwndDlg, IDC_CHECK15);
         extensionPointDisableCheck = GetDlgItem(hwndDlg, IDC_CHECK7);
         disableDynamicCodeCheck = GetDlgItem(hwndDlg, IDC_CHECK8);
         disallowWin32kSyscallsCheck = GetDlgItem(hwndDlg, IDC_CHECK9);
         filterWin32kSyscallsCheck = GetDlgItem(hwndDlg, IDC_CHECK10);
         disableNonSystemFontsCheck = GetDlgItem(hwndDlg, IDC_CHECK11);
         moduleTamperingProtectionCheck = GetDlgItem(hwndDlg, IDC_CHECK12);
         isolateSecurityDomainCheck = GetDlgItem(hwndDlg, IDC_CHECK13);
         cetUserShadowStacksCheck = GetDlgItem(hwndDlg, IDC_CHECK16);


        IO_STATUS_BLOCK ioBlock;
        KSE_SET_PROTECTION protectionCommand;
        KSE_SET_PROTECTION protectionRecv;
        KSE_SET_MITIGATION mitigationCommand;
        KSE_SET_MITIGATION mitigationRecv;

        RtlSecureZeroMemory(&protectionCommand, sizeof(protectionCommand));
        RtlSecureZeroMemory(&protectionRecv, sizeof(protectionRecv));
        RtlSecureZeroMemory(&mitigationCommand, sizeof(mitigationCommand));
        RtlSecureZeroMemory(&mitigationRecv, sizeof(mitigationRecv));

        protectionCommand.ProcessId = processItem->ProcessId;
        mitigationCommand.ProcessId = processItem->ProcessId;

        NTSTATUS status = NtDeviceIoControlFile(ExtenderHandle, NULL, NULL, NULL, &ioBlock, CTL_GET_PROTECTION,
            &protectionCommand, sizeof(protectionCommand), &protectionRecv, sizeof(protectionRecv));
        if (!NT_SUCCESS(status)) {
            MessageBoxW(NULL, L"Could not get process protection.", L"SystemExtender", MB_ICONERROR);
        }
        else {
            processItem->Protection = protectionRecv.Protection;
        }

        status = NtDeviceIoControlFile(ExtenderHandle, NULL, NULL, NULL, &ioBlock, CTL_GET_MITIGATION,
            &mitigationCommand, sizeof(mitigationCommand), &mitigationRecv, sizeof(mitigationRecv));
        if (!NT_SUCCESS(status)) {
            MessageBoxW(NULL, L"Could not get process mitigations.", L"SystemExtender", MB_ICONERROR);
        }
        else {
            Button_SetCheck(controlFlowGuardCheck, mitigationRecv.u.MitigationFlagsValues.ControlFlowGuardEnabled);
            Button_SetCheck(controlFlowGuardStrictCheck, mitigationRecv.u.MitigationFlagsValues.ControlFlowGuardStrict);
            Button_SetCheck(controlFlowGuardExportSupressionCheck, mitigationRecv.u.MitigationFlagsValues.ControlFlowGuardExportSuppressionEnabled);
            Button_SetCheck(disallowStrippedImagesCheck, mitigationRecv.u.MitigationFlagsValues.DisallowStrippedImages);
            Button_SetCheck(forceRelocateImagesCheck, mitigationRecv.u.MitigationFlagsValues.ForceRelocateImages);
            Button_SetCheck(highEntropyAslrCheck, mitigationRecv.u.MitigationFlagsValues.HighEntropyASLREnabled);
            Button_SetCheck(cetUserShadowStacksStrictCheck, mitigationRecv.u2.MitigationFlags2Values.CetUserShadowStacksStrictMode);
            Button_SetCheck(extensionPointDisableCheck, mitigationRecv.u.MitigationFlagsValues.ExtensionPointDisable);
            Button_SetCheck(disableDynamicCodeCheck, mitigationRecv.u.MitigationFlagsValues.DisableDynamicCode);
            Button_SetCheck(disallowWin32kSyscallsCheck, mitigationRecv.u.MitigationFlagsValues.DisallowWin32kSystemCalls);
            Button_SetCheck(filterWin32kSyscallsCheck, mitigationRecv.u.MitigationFlagsValues.EnableFilteredWin32kAPIs);
            Button_SetCheck(disableNonSystemFontsCheck, mitigationRecv.u.MitigationFlagsValues.DisableNonSystemFonts);
            Button_SetCheck(moduleTamperingProtectionCheck, mitigationRecv.u.MitigationFlagsValues.EnableModuleTamperingProtection);
            Button_SetCheck(isolateSecurityDomainCheck, mitigationRecv.u.MitigationFlagsValues.IsolateSecurityDomain);
            Button_SetCheck(cetUserShadowStacksCheck, mitigationRecv.u2.MitigationFlags2Values.CetUserShadowStacks);
        }

        ComboBox_AddString(protectionBox, L"None");
        ComboBox_AddString(protectionBox, L"Light");
        ComboBox_AddString(protectionBox, L"Full");

        ComboBox_AddString(signerBox, L"None");
        ComboBox_AddString(signerBox, L"Authenticode");
        ComboBox_AddString(signerBox, L"CodedGen");
        ComboBox_AddString(signerBox, L"AntiMalware");
        ComboBox_AddString(signerBox, L"Lsa");
        ComboBox_AddString(signerBox, L"Windows");
        ComboBox_AddString(signerBox, L"WinTcb");
        ComboBox_AddString(signerBox, L"WinSystem");
        ComboBox_AddString(signerBox, L"App");

        ComboBox_SetCurSel(protectionBox, processItem->Protection.Type);
        ComboBox_SetCurSel(signerBox, processItem->Protection.Signer);

        SetDlgItemInt(hwndDlg, 1022, mitigationRecv.SignatureLevel, FALSE);
        SetDlgItemInt(hwndDlg, 1023, mitigationRecv.SectionSignatureLevel, FALSE);

        PhInitializeWindowTheme(hwndDlg, !!PhGetIntegerSetting(L"EnableThemeSupport"));
        break;
    }
    case WM_SHOWWINDOW:
    {
        PPH_LAYOUT_ITEM dialogItem;

        if (dialogItem = PhBeginPropPageLayout(hwndDlg, propPageContext))
        {
            PhEndPropPageLayout(hwndDlg, propPageContext);
        }
    }
    case WM_COMMAND:
    {
        switch (GET_WM_COMMAND_ID(wParam, lParam))
        {
        case IDC_BUTTON2:
        {
            IO_STATUS_BLOCK ioBlock;
            KSE_SET_PROTECTION command;

            command.ProcessId = processItem->ProcessId;
            command.Protection.Audit = 0; // If audit is set, it audits our event. Which we don't neeed.
            command.Protection.Type = ComboBox_GetCurSel(protectionBox);
            command.Protection.Signer = ComboBox_GetCurSel(signerBox);

            NTSTATUS status = NtDeviceIoControlFile(ExtenderHandle, NULL, NULL, NULL, &ioBlock, CTL_SET_PROTECTION, &command, sizeof(command), NULL, 0);
            if (!NT_SUCCESS(status)) {
                MessageBoxW(NULL, L"Could not set process protection.", L"SystemExtender", MB_ICONERROR);
            }
            else {
                MessageBoxW(NULL, L"Process protection set!", L"SystemExtender", MB_ICONINFORMATION);
            }
            break;
        }
        case IDC_BUTTON1:
        {
            IO_STATUS_BLOCK ioBlock;
            KSE_SET_MITIGATION command;

            RtlSecureZeroMemory(&command, sizeof(command));
            
            command.ProcessId = processItem->ProcessId;
            command.u.MitigationFlagsValues.ControlFlowGuardEnabled = Button_GetCheck(controlFlowGuardCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.ControlFlowGuardStrict = Button_GetCheck(controlFlowGuardStrictCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.ControlFlowGuardExportSuppressionEnabled= Button_GetCheck(controlFlowGuardExportSupressionCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.DisallowStrippedImages = Button_GetCheck(disallowStrippedImagesCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.ForceRelocateImages = Button_GetCheck(forceRelocateImagesCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.HighEntropyASLREnabled = Button_GetCheck(highEntropyAslrCheck) == BST_CHECKED;
            command.u2.MitigationFlags2Values.CetUserShadowStacksStrictMode = Button_GetCheck(cetUserShadowStacksCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.ExtensionPointDisable = Button_GetCheck(extensionPointDisableCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.DisableDynamicCode = Button_GetCheck(disableDynamicCodeCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.DisallowWin32kSystemCalls = Button_GetCheck(disallowWin32kSyscallsCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.EnableFilteredWin32kAPIs = Button_GetCheck(filterWin32kSyscallsCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.DisableNonSystemFonts = Button_GetCheck(disableNonSystemFontsCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.EnableModuleTamperingProtection = Button_GetCheck(moduleTamperingProtectionCheck) == BST_CHECKED;
            command.u.MitigationFlagsValues.IsolateSecurityDomain = Button_GetCheck(isolateSecurityDomainCheck) == BST_CHECKED;
            command.u2.MitigationFlags2Values.CetUserShadowStacks = Button_GetCheck(cetUserShadowStacksCheck) == BST_CHECKED;
            
            command.SignatureLevel = GetDlgItemInt(hwndDlg, 1022, NULL, FALSE);
            command.SectionSignatureLevel = GetDlgItemInt(hwndDlg, 1022, NULL, FALSE);

            NTSTATUS status = NtDeviceIoControlFile(ExtenderHandle, NULL, NULL, NULL, &ioBlock, CTL_SET_MITIGATION, &command, sizeof(command), NULL, 0);
            if (!NT_SUCCESS(status)) {
                MessageBoxW(NULL, L"Could not set process mitigations.", L"SystemExtender", MB_ICONERROR);
            }
            else {
                MessageBoxW(NULL, L"Process mitigations set!", L"SystemExtender", MB_ICONINFORMATION);
            }
            break;
        }
        }
    }
    }

    return 0;
}
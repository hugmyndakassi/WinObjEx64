/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       UI.C
*
*  VERSION:     1.22
*
*  DATE:        03 Oct 2025
*
*  WinObjEx64 ImageScope UI.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

INT_PTR CALLBACK TabsWndProc(
    _In_ HWND hWnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

static IMS_TAB imsTabs[] = {
    { IDD_TABDLG_SECTION, TabIdSection, TabsWndProc, TEXT("Section") },
    { IDD_TABDLG_VSINFO, TabIdVSInfo, TabsWndProc, TEXT("VersionInfo") },
    { IDD_TABDLG_STRINGS, TabIdStrings, TabsWndProc, TEXT("Strings") }
};

static VALUE_DESC peImageFileChars[] = {
    { TEXT("RelocsStripped"), IMAGE_FILE_RELOCS_STRIPPED },
    { TEXT("Executable"), IMAGE_FILE_EXECUTABLE_IMAGE },
    { TEXT("LineNumsStripped"), IMAGE_FILE_LINE_NUMS_STRIPPED },
    { TEXT("SymsStripped"), IMAGE_FILE_LOCAL_SYMS_STRIPPED },
    { TEXT("AggressiveWsTrim"), IMAGE_FILE_AGGRESIVE_WS_TRIM },
    { TEXT("LargeAddressAware"), IMAGE_FILE_LARGE_ADDRESS_AWARE },
    { TEXT("32bit"), IMAGE_FILE_32BIT_MACHINE },
    { TEXT("DebugStripped"), IMAGE_FILE_DEBUG_STRIPPED },
    { TEXT("RemovableRunFromSwap"), IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP },
    { TEXT("NetRunFromSwap"), IMAGE_FILE_NET_RUN_FROM_SWAP },
    { TEXT("System"), IMAGE_FILE_SYSTEM },
    { TEXT("Dll"), IMAGE_FILE_DLL },
    { TEXT("UpSystemOnly"), IMAGE_FILE_UP_SYSTEM_ONLY }
};

static VALUE_DESC peDllChars[] = {
    { TEXT("HighEntropyVA"), IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA },
    { TEXT("DynamicBase"), IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE },
    { TEXT("ForceIntegrity"), IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY },
    { TEXT("NXCompat"), IMAGE_DLLCHARACTERISTICS_NX_COMPAT },
    { TEXT("NoIsolation"), IMAGE_DLLCHARACTERISTICS_NO_ISOLATION },
    { TEXT("NoSEH"), IMAGE_DLLCHARACTERISTICS_NO_SEH },
    { TEXT("NoBind"), IMAGE_DLLCHARACTERISTICS_NO_BIND },
    { TEXT("AppContainer"), IMAGE_DLLCHARACTERISTICS_APPCONTAINER },
    { TEXT("WDMDriver"), IMAGE_DLLCHARACTERISTICS_WDM_DRIVER },
    { TEXT("GuardCF"), IMAGE_DLLCHARACTERISTICS_GUARD_CF },
    { TEXT("TerminalServerAware"), IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE }
};

typedef enum _ValueDumpType {
    UlongDump = 0,
    UShortDump,
    UCharDump,
    BooleanDump,
    InvalidDumpType
} ValueDumpType;

VOID SectionDumpUlong(
    _In_ HWND treeList,
    _In_ HTREEITEM rootItem,
    _In_ ULONG value,
    _In_ LPWSTR valueName,
    _In_opt_ LPWSTR valueDesc,
    _In_ ValueDumpType dumpType
)
{
    TL_SUBITEMS_FIXED subItems;
    LPWSTR lpFormat;
    WCHAR szText[PRINTF_BUFFER_LENGTH];

    RtlSecureZeroMemory(&subItems, sizeof(subItems));
    szText[0] = 0;
    subItems.Count = 2;
    subItems.Text[0] = szText;

    if (valueDesc)
        subItems.Text[1] = valueDesc;
    else
        subItems.Text[1] = EMPTY_STRING;

    switch (dumpType) {
    case UShortDump:
        lpFormat = TEXT("0x%hX");
        break;
    case UCharDump:
        lpFormat = TEXT("0x%02X");
        break;
    case BooleanDump:
        lpFormat = TEXT("%01u");
        break;
    case UlongDump:
    default:
        lpFormat = TEXT("0x%08lX");
        break;
    }

    StringCchPrintf(
        szText,
        PRINTF_BUFFER_LENGTH,
        lpFormat,
        value);

    supTreeListAddItem(
        treeList,
        rootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        valueName,
        &subItems);
}

VOID SectionDumpFlags(
    _In_ HWND treeList,
    _In_ HTREEITEM rootItem,
    _In_ ULONG flags,
    _In_ PVALUE_DESC flagsDescriptions,
    _In_ ULONG maxDescriptions,
    _In_ LPWSTR valueName,
    _In_ ValueDumpType dumpType
)
{
    UINT i, j;
    LPWSTR lpType;
    ULONG scanFlags = flags;
    TL_SUBITEMS_FIXED subItems;

    WCHAR szValue[PRINTF_BUFFER_LENGTH];

    RtlSecureZeroMemory(&szValue, sizeof(szValue));
    RtlSecureZeroMemory(&subItems, sizeof(subItems));

    j = 0;
    lpType = NULL;
    if (scanFlags) {
        for (i = 0; i < maxDescriptions; i++) {
            if (scanFlags & flagsDescriptions[i].dwValue) {
                lpType = flagsDescriptions[i].lpDescription;
                subItems.Count = 2;

                //add first entry with name
                if (j == 0) {
                    StringCchPrintf(szValue, PRINTF_BUFFER_LENGTH,
                        TEXT("0x%08lX"), scanFlags);

                    subItems.Text[0] = szValue;
                    subItems.Text[1] = lpType;
                }
                else {
                    //add subentry
                    subItems.Text[0] = EMPTY_STRING;
                    subItems.Text[1] = lpType;
                }

                supTreeListAddItem(
                    treeList,
                    rootItem,
                    TVIF_TEXT | TVIF_STATE,
                    0,
                    0,
                    (j == 0) ? valueName : EMPTY_STRING,
                    &subItems);

                scanFlags &= ~flagsDescriptions[i].dwValue;
                j++;
            }
            if (scanFlags == 0) {
                break;
            }
        }
    }
    else {
        SectionDumpUlong(treeList, rootItem, flags, valueName, NULL, dumpType);
    }
}

VOID SectionDumpUnicodeString(
    _In_ HWND treeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR stringName,
    _In_ PUNICODE_STRING pString,
    _In_ DWORD itemState,
    _In_ DWORD stateMask
)
{
    HTREEITEM           hSubItem;
    TL_SUBITEMS_FIXED   subItems;
    WCHAR               szValue[PRINTF_BUFFER_LENGTH];

    RtlSecureZeroMemory(&subItems, sizeof(subItems));
    subItems.Count = 2;

    subItems.Text[0] = EMPTY_STRING;
    subItems.Text[1] = TEXT("UNICODE_STRING");

    hSubItem = supTreeListAddItem(
        treeList,
        hParent,
        TVIF_TEXT | TVIF_STATE,
        itemState,
        stateMask,
        stringName,
        &subItems);

    //
    // Add UNICODE_STRING.Length
    //
    RtlSecureZeroMemory(&subItems, sizeof(subItems));
    RtlSecureZeroMemory(szValue, sizeof(szValue));

    StringCchPrintf(
        szValue,
        RTL_NUMBER_OF(szValue),
        TEXT("0x%hX"),
        pString->Length);

    subItems.Count = 2;
    subItems.Text[0] = szValue;
    subItems.Text[1] = EMPTY_STRING;

    supTreeListAddItem(
        treeList,
        hSubItem,
        TVIF_TEXT,
        0,
        0,
        TEXT("Length"),
        &subItems);

    //
    // Add UNICODE_STRING.MaximumLength
    //
    RtlSecureZeroMemory(szValue, sizeof(szValue));
    RtlSecureZeroMemory(&subItems, sizeof(subItems));

    StringCchPrintf(
        szValue,
        RTL_NUMBER_OF(szValue),
        TEXT("0x%hX"),
        pString->MaximumLength);

    subItems.Count = 2;
    subItems.Text[0] = szValue;
    subItems.Text[1] = EMPTY_STRING;

    supTreeListAddItem(
        treeList,
        hSubItem,
        TVIF_TEXT,
        0,
        0,
        TEXT("MaximumLength"),
        &subItems);

    //
    // Add UNICODE_STRING.Buffer
    //
    RtlSecureZeroMemory(&subItems, sizeof(subItems));
    subItems.Count = 2;

    if (pString->Buffer == NULL) {
        subItems.Text[0] = TEXT("NULL");
        subItems.Text[1] = EMPTY_STRING;
    }
    else {
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = TEXT('0');
        szValue[1] = TEXT('x');
        u64tohex((ULONG_PTR)pString->Buffer, &szValue[2]);
        subItems.Text[0] = szValue;
        subItems.Text[1] = pString->Buffer;
    }

    supTreeListAddItem(
        treeList,
        hSubItem,
        TVIF_TEXT,
        0,
        0,
        TEXT("Buffer"),
        &subItems);
}

VOID SectionDumpImageFileName(
    _In_ GUI_CONTEXT* context
)
{
    OBJECT_NAME_INFORMATION* objectNameInfo = NULL;
    PVOID baseAddress = context->SectionAddress;
    NTSTATUS ntStatus;
    SIZE_T returnedLength = 0;
    HTREEITEM tviRoot;

    do {
        ntStatus = NtQueryVirtualMemory(
            NtCurrentProcess(),
            baseAddress,
            MemoryMappedFilenameInformation,
            NULL,
            0,
            &returnedLength);

        if (ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;

        //
        // Allocate required buffer.
        //      
        objectNameInfo = (OBJECT_NAME_INFORMATION*)supHeapAlloc(returnedLength);
        if (objectNameInfo == NULL)
            break;

        //
        // Query information.
        //
        ntStatus = NtQueryVirtualMemory(
            NtCurrentProcess(),
            baseAddress,
            MemoryMappedFilenameInformation,
            objectNameInfo,
            returnedLength,
            &returnedLength);

        if (NT_SUCCESS(ntStatus)) {
            tviRoot = supTreeListAddItem(
                context->TreeList,
                NULL,
                TVIF_TEXT | TVIF_STATE,
                (UINT)TVIS_EXPANDED,
                (UINT)TVIS_EXPANDED,
                TEXT("OBJECT_NAME_INFORMATION"),
                NULL);

            if (tviRoot) {
                SectionDumpUnicodeString(
                    context->TreeList,
                    tviRoot,
                    TEXT("Name"),
                    &objectNameInfo->Name,
                    TVIS_EXPANDED,
                    TVIS_EXPANDED);
            }
        }
    } while (FALSE);

    if (objectNameInfo)
        supHeapFree(objectNameInfo);
}

VOID SectionDumpStructs(
    _In_ GUI_CONTEXT* context
)
{
    BOOL bInternalPresent = FALSE;
    SECTION_IMAGE_INFORMATION sii;
    SECTION_INTERNAL_IMAGE_INFORMATION sii2;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE sectionHandle = NULL;
    SIZE_T returnLength;

    WCHAR szText[PRINTF_BUFFER_LENGTH];

    LPWSTR lpDesc;
    HTREEITEM tviRoot;
    TL_SUBITEMS_FIXED subItems;

    __try {
        ntStatus = context->ParamBlock.OpenNamedObjectByType(
            &sectionHandle,
            ObjectTypeSection,
            &context->ParamBlock.Object.Directory,
            &context->ParamBlock.Object.Name,
            SECTION_QUERY);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        ntStatus = NtQuerySection(
            sectionHandle,
            SectionImageInformation,
            &sii,
            sizeof(SECTION_IMAGE_INFORMATION),
            &returnLength);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        bInternalPresent = NT_SUCCESS(NtQuerySection(
            sectionHandle,
            SectionInternalImageInformation,
            &sii2,
            sizeof(SECTION_INTERNAL_IMAGE_INFORMATION),
            &returnLength));

        NtClose(sectionHandle);
        sectionHandle = NULL;

        tviRoot = supTreeListAddItem(
            context->TreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            (UINT)TVIS_EXPANDED,
            (UINT)TVIS_EXPANDED,
            TEXT("SECTION_IMAGE_INFORMATION"),
            NULL);

        if (tviRoot) {
            RtlSecureZeroMemory(&subItems, sizeof(subItems));
            szText[0] = 0;
            subItems.Count = 2;
            subItems.Text[0] = szText;
            subItems.Text[1] = EMPTY_STRING;

            StringCchPrintf(szText, PRINTF_BUFFER_LENGTH, TEXT("0x%p"), sii.TransferAddress);
            supTreeListAddItem(
                context->TreeList,
                tviRoot,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                TEXT("TransferAddress"),
                &subItems);

            SectionDumpUlong(context->TreeList, tviRoot,
                sii.ZeroBits, TEXT("ZeroBits"), NULL, UlongDump);

            StringCchPrintf(szText, PRINTF_BUFFER_LENGTH, TEXT("0x%I64X"), sii.MaximumStackSize);
            supTreeListAddItem(
                context->TreeList,
                tviRoot,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                TEXT("MaximumStackSize"),
                &subItems);

            StringCchPrintf(szText, PRINTF_BUFFER_LENGTH, TEXT("0x%I64X"), sii.CommittedStackSize);
            supTreeListAddItem(
                context->TreeList,
                tviRoot,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                TEXT("CommittedStackSize"),
                &subItems);

            switch (sii.SubSystemType) {
            case IMAGE_SUBSYSTEM_NATIVE:
                lpDesc = TEXT("Native");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_GUI:
                lpDesc = TEXT("Windows GUI");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_CUI:
                lpDesc = TEXT("Windows Console");
                break;
            case IMAGE_SUBSYSTEM_OS2_CUI:
                lpDesc = TEXT("OS/2 Console");
                break;
            case IMAGE_SUBSYSTEM_POSIX_CUI:
                lpDesc = TEXT("Posix Console");
                break;
            case IMAGE_SUBSYSTEM_XBOX:
                lpDesc = TEXT("XBox");
                break;
            case IMAGE_SUBSYSTEM_EFI_APPLICATION:
                lpDesc = TEXT("EFI Application");
                break;
            case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
                lpDesc = TEXT("EFI Boot Service Driver");
                break;
            case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
                lpDesc = TEXT("EFI Runtime Driver");
                break;
            case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
                lpDesc = TEXT("Windows Boot Application");
                break;
            case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
                lpDesc = TEXT("XBox Code Catalog");
                break;
            default:
                lpDesc = TEXT("Unknown");
                break;
            }

            SectionDumpUlong(context->TreeList, tviRoot,
                sii.SubSystemType, TEXT("SubSystemType"), lpDesc, UlongDump);

            StringCchPrintf(
                szText,
                PRINTF_BUFFER_LENGTH,
                TEXT("%hu.%hu"),
                sii.SubSystemMajorVersion,
                sii.SubSystemMinorVersion);

            SectionDumpUlong(context->TreeList, tviRoot,
                sii.SubSystemVersion, TEXT("SubSystemVersion"), szText, UlongDump);

            StringCchPrintf(
                szText,
                PRINTF_BUFFER_LENGTH,
                TEXT("%hu.%hu"),
                sii.MajorOperatingSystemVersion,
                sii.MinorOperatingSystemVersion);

            SectionDumpUlong(context->TreeList, tviRoot,
                sii.OperatingSystemVersion, TEXT("OperatingSystemVersion"), szText, UlongDump);

            SectionDumpFlags(context->TreeList, tviRoot,
                sii.ImageCharacteristics,
                peImageFileChars,
                RTL_NUMBER_OF(peImageFileChars),
                TEXT("ImageCharacteristics"),
                UShortDump);

            SectionDumpFlags(context->TreeList, tviRoot,
                sii.DllCharacteristics,
                peDllChars,
                RTL_NUMBER_OF(peDllChars),
                TEXT("DllCharacteristics"),
                UShortDump);

            switch (sii.Machine) {
            case IMAGE_FILE_MACHINE_I386:
                lpDesc = TEXT("Intel386");
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                lpDesc = TEXT("AMD64");
                break;
            default:
                lpDesc = TEXT("Unknown/Unsupported Machine");
                break;
            }

            SectionDumpUlong(context->TreeList, tviRoot,
                sii.Machine, TEXT("Machine"), lpDesc, UShortDump);

            SectionDumpUlong(context->TreeList, tviRoot,
                (ULONG)sii.ImageContainsCode, TEXT("ImageContainsCode"), NULL, BooleanDump);

            SectionDumpUlong(context->TreeList, tviRoot,
                (ULONG)sii.ImageFlags, TEXT("ImageFlags"), NULL, UCharDump);

            SectionDumpUlong(context->TreeList, tviRoot,
                sii.LoaderFlags, TEXT("LoaderFlags"), NULL, UlongDump);

            SectionDumpUlong(context->TreeList, tviRoot,
                sii.ImageFileSize, TEXT("ImageFileSize"), NULL, UlongDump);

            SectionDumpUlong(context->TreeList, tviRoot,
                sii.CheckSum, TEXT("CheckSum"), NULL, UlongDump);
        }

        SectionDumpImageFileName(context);

        if (bInternalPresent == FALSE)
            __leave;

        tviRoot = supTreeListAddItem(
            context->TreeList,
            NULL,
            TVIF_TEXT | TVIF_STATE,
            (UINT)TVIS_EXPANDED,
            (UINT)TVIS_EXPANDED,
            TEXT("SECTION_INTERNAL_IMAGE_INFORMATION"),
            NULL);

        if (tviRoot) {
            SectionDumpUlong(context->TreeList, tviRoot,
                sii2.ExtendedFlags, TEXT("ExtendedFlags"), NULL, UlongDump);
        }
    }
    __finally {
        if (sectionHandle)
            NtClose(sectionHandle);

        if (!NT_SUCCESS(ntStatus)) {
            StringCchPrintf(szText,
                _countof(szText),
                TEXT("Query status 0x%lx"), ntStatus);
        }
        else {
            _strcpy(szText, TEXT("Query - OK"));
        }

        supStatusBarSetText(
            context->StatusBar,
            0,
            szText);
    }
}

/*
* VsInfoStringsEnumCallback
*
* Purpose:
*
* VERSION_INFO enumeration callback.
*
*/
BOOL CALLBACK VsInfoStringsEnumCallback(
    _In_ PWCHAR key,
    _In_ PWCHAR value,
    _In_ PWCHAR langId,
    _In_opt_ LPVOID cbparam
)
{
    LV_ITEM lvItem;
    INT itemIndex;
    HWND hwndList = (HWND)cbparam;
    WCHAR szLangId[128];

    if (hwndList == 0)
        return 0;

    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
    lvItem.mask = LVIF_TEXT;
    lvItem.pszText = key;
    lvItem.iItem = MAXINT;
    itemIndex = ListView_InsertItem(hwndList, &lvItem);

    lvItem.iSubItem = 1;
    lvItem.pszText = value;
    lvItem.iItem = itemIndex;
    ListView_SetItem(hwndList, &lvItem);

    szLangId[0] = 0;
    StringCchPrintf(szLangId, _countof(szLangId), TEXT("0x%ws"), langId);

    lvItem.iSubItem = 2;
    lvItem.pszText = szLangId;
    lvItem.iItem = itemIndex;
    ListView_SetItem(hwndList, &lvItem);

    return TRUE; // continue enum
}

/*
* VsInfoTabOnInit
*
* Purpose:
*
* Initialize VersionInfo tab dialog page.
*
*/
VOID VsInfoTabOnInit(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* context
)
{
    WCHAR szText[100];
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);

    supAddListViewColumn(hwndList,
        0,
        0,
        0,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("Name"),
        120,
        context->CurrentDPI);

    supAddListViewColumn(hwndList,
        1,
        1,
        1,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("Value"),
        300,
        context->CurrentDPI);

    supAddListViewColumn(hwndList,
        2,
        2,
        2,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("LangId"),
        100,
        context->CurrentDPI);

    ListView_SetExtendedListViewStyle(hwndList,
        LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);

    SetWindowTheme(hwndList, TEXT("Explorer"), NULL);

    SendMessage(hwndList, WM_SETREDRAW, (WPARAM)FALSE, (LPARAM)0);

    if (PEImageEnumVersionFields(
        context->SectionAddress,
        &VsInfoStringsEnumCallback,
        NULL,
        (LPVOID)hwndList))
    {
        StringCchCopy(szText, _countof(szText), TEXT("Query - OK"));
    }
    else {
        StringCchPrintf(
            szText,
            _countof(szText),
            TEXT("Query Error 0x%lx"), GetLastError());
    }

    SendMessage(hwndList, WM_SETREDRAW, (WPARAM)TRUE, (LPARAM)0);

    supStatusBarSetText(
        context->StatusBar,
        0,
        szText);
}

/*
* SectionTabOnInit
*
* Purpose:
*
* Initialize Section tab dialog page.
*
*/
VOID SectionTabOnInit(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* context
)
{
    RECT rc;
    HWND hwndList;
    HDITEM hdrItem;

    GetClientRect(hWndDlg, &rc);

    TabCtrl_AdjustRect(context->TabHeader->hwndTab, FALSE, &rc);

    hwndList = CreateWindowEx(WS_EX_STATICEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND | TLSTYLE_LINKLINES,
        rc.left,
        rc.top,
        rc.right,
        rc.bottom,
        hWndDlg, NULL, NULL, NULL);

    if (hwndList) {
        RtlSecureZeroMemory(&hdrItem, sizeof(hdrItem));
        hdrItem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
        hdrItem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
        hdrItem.cxy = ScaleDPI(220, context->CurrentDPI);
        hdrItem.pszText = TEXT("Field");
        TreeList_InsertHeaderItem(hwndList, 0, &hdrItem);
        hdrItem.cxy = ScaleDPI(130, context->CurrentDPI);
        hdrItem.pszText = TEXT("Value");
        TreeList_InsertHeaderItem(hwndList, 1, &hdrItem);
        hdrItem.cxy = ScaleDPI(210, context->CurrentDPI);
        hdrItem.pszText = TEXT("Additional Information");
        TreeList_InsertHeaderItem(hwndList, 2, &hdrItem);

        context->TreeList = hwndList;
        SectionDumpStructs(context);
    }
}

#pragma warning(push)
#pragma warning(disable: 6262)
UINT AddStringsToList(
    _In_ HWND hWndDlg,
    _In_ PVOID baseAddress,
    _In_ PSTRING_PTR chainHead,
    _In_ BOOLEAN isUnicode
)
{
    INT nLength, iItem;
    UINT stringCount = 0;
    PSTRING_PTR chain = chainHead;
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);
    LV_ITEM lvItem;
    WCHAR szBuffer[UNICODE_STRING_MAX_CHARS];

    RtlZeroMemory(szBuffer, sizeof(szBuffer));

    lvItem.mask = LVIF_TEXT;

    while (chain) {
        if (isUnicode) {
            _strncpy(szBuffer,
                UNICODE_STRING_MAX_CHARS,
                (PWCHAR)RtlOffsetToPointer(baseAddress, chain->ofpstr),
                chain->length);

            nLength = chain->length;
        }
        else {
            nLength = MultiByteToWideChar(CP_ACP, 0,
                (PCHAR)RtlOffsetToPointer(baseAddress, chain->ofpstr),
                chain->length,
                szBuffer,
                UNICODE_STRING_MAX_CHARS);

            if (nLength)
                szBuffer[nLength] = 0;
        }

        if (nLength) {
            lvItem.pszText = szBuffer;
            lvItem.iItem = INT_MAX;
            lvItem.iSubItem = 0;
            iItem = ListView_InsertItem(hwndList, &lvItem);

            lvItem.pszText = (isUnicode) ? TEXT("U") : TEXT("A");
            lvItem.iSubItem = 1;
            lvItem.iItem = iItem;
            ListView_SetItem(hwndList, &lvItem);

            stringCount++;
        }

        chain = chain->pnext;
    }

    return stringCount;
}
#pragma warning(pop)

VOID ScanRegions(
    _In_ HWND hWndDlg,
    _In_ HANDLE scanHeap,
    _In_ GUI_CONTEXT* context
)
{
    ULONG cAnsi = 0;
    ULONG cUnicode = 0;

    NTSTATUS ntStatus;
    SIZE_T totalLength = context->SectionViewSize, curPos = 0, dummy;
    PVOID baseAddress = context->SectionAddress;
    PSTRING_PTR chain = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    WCHAR szBuffer[100];

    RtlZeroMemory(&mbi, sizeof(mbi));

    do {
        ntStatus = NtQueryVirtualMemory(
            NtCurrentProcess(),
            baseAddress,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &dummy);

        if (NT_SUCCESS(ntStatus)) {
            curPos += mbi.RegionSize;

            if (mbi.State & MEM_COMMIT) {
                if (!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                    if (mbi.Protect & (PAGE_READONLY |
                        PAGE_READWRITE |
                        PAGE_EXECUTE |
                        PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE))
                    {
                        chain = EnumImageStringsA(
                            scanHeap,
                            baseAddress,
                            (ULONG)mbi.RegionSize);

                        if (chain) {
                            cAnsi += AddStringsToList(
                                hWndDlg,
                                baseAddress,
                                chain,
                                FALSE);
                        }

                        chain = EnumImageStringsW(
                            scanHeap,
                            baseAddress,
                            (ULONG)mbi.RegionSize);

                        if (chain) {
                            cUnicode += AddStringsToList(
                                hWndDlg,
                                baseAddress,
                                chain,
                                TRUE);
                        }
                    }
                }
            }
        }
        else {
            curPos += PAGE_SIZE;
        }

        baseAddress = RtlOffsetToPointer(context->SectionAddress, curPos);

    } while (curPos < totalLength);

    StringCchPrintf(
        szBuffer,
        _countof(szBuffer),
        TEXT("Strings: %lu (A: %lu, U: %lu)"),
        cAnsi + cUnicode,
        cAnsi, cUnicode);

    supStatusBarSetText(
        context->StatusBar,
        0,
        szBuffer);
}

/*
* StringsTabOnShow
*
* Purpose:
*
* Strings page WM_SHOWWINDOW handler.
*
*/
VOID StringsTabOnShow(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* context
)
{
    PVOID heapHandle = NULL;
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);

    __try {
        SendMessage(hwndList, WM_SETREDRAW, (WPARAM)FALSE, (LPARAM)0);
        supSetWaitCursor(TRUE);

        heapHandle = HeapCreate(0, UNICODE_STRING_MAX_CHARS * sizeof(WCHAR), 0);
        if (heapHandle) {
            ScanRegions(
                hWndDlg,
                heapHandle,
                context);

            HeapDestroy(heapHandle);
            heapHandle = NULL;
        }
    }
    __finally {
        SendMessage(hwndList, WM_SETREDRAW, (WPARAM)TRUE, (LPARAM)0);
        supSetWaitCursor(FALSE);
        if (heapHandle)
            HeapDestroy(heapHandle);
    }
}

/*
* StringsTabOnInit
*
* Purpose:
*
* Initialize Strings tab page dialog.
*
*/
VOID StringsTabOnInit(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* context
)
{
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);

    if (hwndList) {
        supAddListViewColumn(hwndList,
            0,
            0,
            0,
            I_IMAGENONE,
            LVCFMT_LEFT,
            TEXT("String"),
            MAX_PATH,
            context->CurrentDPI);

        supAddListViewColumn(hwndList,
            1,
            1,
            1,
            I_IMAGENONE,
            LVCFMT_CENTER,
            TEXT("Type"),
            80,
            context->CurrentDPI);

        ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        SetWindowTheme(hwndList, TEXT("Explorer"), NULL);
    }
}

/*
* TabOnInit
*
* Purpose:
*
* Tab window WM_INITDIALOG handler.
*
*/
VOID TabOnInit(
    _In_ HWND hWndDlg,
    _In_ GUI_CONTEXT* context
)
{
    INT iSel;

    if (context == NULL)
        return;

    iSel = TabCtrl_GetCurSel(context->TabHeader->hwndTab);

    switch (iSel) {
    case TabIdSection:
        SectionTabOnInit(hWndDlg, context);
        break;
    case TabIdVSInfo:
        VsInfoTabOnInit(hWndDlg, context);
        break;
    case TabIdStrings:
        StringsTabOnInit(hWndDlg, context);
        break;
    default:
        break;
    }
}

/*
* TabOnShow
*
* Purpose:
*
* Tab window WM_SHOWWINDOW handler.
*
*/
INT_PTR TabOnShow(
    _In_ HWND hWndDlg,
    _In_ BOOL fShow
)
{
    INT iSel;
    GUI_CONTEXT* context = GetProp(hWndDlg, T_IMS_PROP);

    if (context == NULL)
        return 0;

    iSel = TabCtrl_GetCurSel(context->TabHeader->hwndTab);

    switch (iSel) {
    case TabIdStrings:
        if (fShow)
            StringsTabOnShow(hWndDlg, context);
        break;
    default:
        break;
    }

    return 1;
}

/*
* TabsOnContextMenu
*
* Purpose:
*
* Tab control WM_CONTEXTMENU handler.
*
*/
VOID TabsOnContextMenu(
    _In_ HWND hWndDlg
)
{
    INT iSel;
    UINT uPos = 0;
    POINT pt1;
    HMENU hMenu;
    GUI_CONTEXT* context = GetProp(hWndDlg, T_IMS_PROP);

    if (context == NULL)
        return;

    iSel = TabCtrl_GetCurSel(context->TabHeader->hwndTab);

    switch (iSel) {
    case TabIdVSInfo:
    case TabIdStrings:
        if (GetCursorPos(&pt1)) {
            hMenu = CreatePopupMenu();
            if (hMenu) {
                //
                // Add "Copy %item%" menu item.
                //
                if (supListViewAddCopyValueItem(hMenu,
                    GetDlgItem(hWndDlg, IDC_LIST),
                    ID_MENU_LIST_COPY,
                    uPos,
                    &pt1,
                    &context->LvItemHit,
                    &context->LvColumnHit))
                {
                    uPos++;
                    InsertMenu(hMenu, uPos++, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
                }

                InsertMenu(hMenu, uPos, MF_BYCOMMAND, ID_MENU_LIST_DUMP, T_EXPORTTOFILE);
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hWndDlg, NULL);
                DestroyMenu(hMenu);
            }
        }
        break;
    default:
        break;
    }
}

VOID TabsDumpList(
    _In_ HWND hWndDlg
)
{
    INT iSel;
    LPWSTR lpFileName;
    GUI_CONTEXT* context = GetProp(hWndDlg, T_IMS_PROP);
    HWND hwndList = GetDlgItem(hWndDlg, IDC_LIST);

    if (context == NULL)
        return;

    iSel = TabCtrl_GetCurSel(context->TabHeader->hwndTab);

    switch (iSel) {
    case TabIdVSInfo:
        lpFileName = TEXT("VersionInfo.csv");
        break;
    case TabIdStrings:
        lpFileName = TEXT("Strings.csv");
        break;
    default:
        return;
    }

    supListViewExportToFile(lpFileName, hWndDlg, hwndList, T_CSV_FILE_FILTER);
}

VOID TabsListViewCopyItem(
    _In_ HWND hWndDlg
)
{
    GUI_CONTEXT* context = GetProp(hWndDlg, T_IMS_PROP);

    if (context) {
        supListViewCopyItemValueToClipboard(GetDlgItem(hWndDlg, IDC_LIST),
            context->LvItemHit,
            context->LvColumnHit);
    }
}

/*
* TabsWndProc
*
* Purpose:
*
* Tab control window handler.
*
*/
INT_PTR CALLBACK TabsWndProc(
    _In_ HWND hWnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    switch (uMsg) {
    case WM_INITDIALOG:
        SetProp(hWnd, T_IMS_PROP, (HANDLE)lParam);
        TabOnInit(hWnd, (GUI_CONTEXT*)lParam);
        break;

    case WM_COMMAND:
        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case ID_MENU_LIST_DUMP:
            TabsDumpList(hWnd);
            break;

        case ID_MENU_LIST_COPY:
            TabsListViewCopyItem(hWnd);
            break;

        default:
            break;
        }
        break;

    case WM_CONTEXTMENU:
        TabsOnContextMenu(hWnd);
        break;

    case WM_SHOWWINDOW:
        return TabOnShow(hWnd, (wParam != 0));

    case WM_DESTROY:
        RemoveProp(hWnd, T_IMS_PROP);
        break;

    default:
        return 0;
    }

    return 1;
}

/*
* OnTabResize
*
* Purpose:
*
* Tab window WM_RESIZE handler.
*
*/
VOID CALLBACK OnTabResize(
    _In_ TABHDR* tabHeader
)
{
    RECT hwndRect;
    INT iSel;
    HWND hwndList = 0;
    GUI_CONTEXT* context;

    context = (GUI_CONTEXT*)GetProp(tabHeader->hwndDisplay, T_IMS_PROP);
    if (context == NULL)
        return;

    iSel = TabCtrl_GetCurSel(tabHeader->hwndTab);
    GetClientRect(tabHeader->hwndDisplay, &hwndRect);

    switch (iSel) {
    case TabIdSection:
        hwndList = context->TreeList;
        break;

    case TabIdVSInfo:
    case TabIdStrings:
        hwndList = GetDlgItem(tabHeader->hwndDisplay, IDC_LIST);
        break;

    default:
        return;
    }

    if (hwndList == NULL)
        return;

    GetClientRect(tabHeader->hwndDisplay, &hwndRect);

    TabCtrl_AdjustRect(tabHeader->hwndTab, FALSE, &hwndRect);

    SetWindowPos(hwndList,
        HWND_TOP,
        0,
        0,
        hwndRect.right,
        hwndRect.bottom,
        SWP_NOOWNERZORDER);
}

/*
* OnResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
VOID OnResize(
    _In_ HWND hWnd
)
{
    GUI_CONTEXT* context;
    RECT r, szr;

    context = (GUI_CONTEXT*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (context) {
        SendMessage(context->StatusBar, WM_SIZE, 0, 0);

        GetClientRect(hWnd, &r);
        GetClientRect(context->StatusBar, &szr);

        //resize of the tab control
        if (context->TabHeader != NULL) {
            SetWindowPos(
                context->TabHeader->hwndTab,
                HWND_TOP,
                0,
                0,
                r.right,
                r.bottom - szr.bottom,
                SWP_NOACTIVATE | SWP_NOZORDER);

            TabResizeTabWindow(context->TabHeader);
        }
    }
}

/*
* OnNotify
*
* Purpose:
*
* WM_NOTIFY handler.
*
*/
VOID OnNotify(
    _In_ HWND hWnd,
    _In_ LPNMHDR nmhdr
)
{
    GUI_CONTEXT* context;

    if (InterlockedAdd((PLONG)&g_pluginState, PLUGIN_RUNNING) == PLUGIN_STOP)
        return;

    context = (GUI_CONTEXT*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (context) {
        TabOnChangeTab(context->TabHeader, nmhdr);
    }
}

VOID OnGetMinMax(
    _In_ HWND hWnd,
    _In_ PMINMAXINFO mmInfo
)
{
    GUI_CONTEXT* context;
    context = (GUI_CONTEXT*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (context) {
        mmInfo->ptMinTrackSize.x = ScaleDPI(640, context->CurrentDPI);
        mmInfo->ptMinTrackSize.y = ScaleDPI(480, context->CurrentDPI);
    }
}

/*
* MainWindowProc
*
* Purpose:
*
* Main window procedure.
*
*/
LRESULT CALLBACK MainWindowProc(
    _In_ HWND hWnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    switch (uMsg) {
    case WM_CLOSE:
        PostQuitMessage(0);
        break;

    case WM_SIZE:
        OnResize(hWnd);
        break;

    case WM_NOTIFY:
        OnNotify(hWnd, (LPNMHDR)lParam);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            OnGetMinMax(hWnd, (PMINMAXINFO)lParam);
        }
        break;

    default:
        break;
    }

    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

/*
* RunUI
*
* Purpose:
*
* Create main window, run message loop.
*
*/
BOOL RunUI(
    _In_ GUI_CONTEXT* context
)
{
    INT i;
    INITCOMMONCONTROLSEX icex;

    BOOL rv;
    MSG msg1;
    LPWSTR lpTitle;
    WCHAR szClassName[100];

    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icex);

#pragma warning(push)
#pragma warning(disable: 6031)
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
#pragma warning(pop)

    context->CurrentDPI = context->ParamBlock.CurrentDPI;

    context->LvColumnHit = -1;
    context->LvItemHit = -1;

    //
    // Window class once.
    //
    StringCchPrintf(szClassName,
        RTL_NUMBER_OF(szClassName),
        TEXT("%wsWndClass"),
        g_plugin->Name);

    lpTitle = IMAGESCOPE_WNDTITLE;

    //
    // Create main window.
    //
    context->MainWindow = CreateWindowEx(
        0,
        szClassName,
        lpTitle,
        WS_VISIBLE | WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        ScaleDPI(640, context->CurrentDPI),
        ScaleDPI(480, context->CurrentDPI),
        NULL,
        NULL,
        g_thisDll,
        NULL);

    if (context->MainWindow == 0) {
        kdDebugPrint("Could not create main window, err = %lu\r\n", GetLastError());
        return FALSE;
    }

    SetWindowLongPtr(context->MainWindow, GWLP_USERDATA, (LONG_PTR)context);

    //
    // Status Bar window.
    //
    context->StatusBar = CreateWindowEx(
        0,
        STATUSCLASSNAME,
        NULL,
        WS_VISIBLE | WS_CHILD,
        0,
        0,
        0,
        0,
        context->MainWindow,
        NULL,
        g_thisDll,
        NULL);

    if (context->StatusBar == 0) {
        kdDebugPrint("Could not create statusbar window, err = %lu\r\n", GetLastError());
        return FALSE;
    }

    context->TabHeader = TabCreateControl(
        g_thisDll,
        context->MainWindow,
        NULL,
        NULL,
        (TABRESIZECALLBACK)&OnTabResize,
        (TABCALLBACK_ALLOCMEM)&supHeapAlloc,
        (TABCALLBACK_FREEMEM)&supHeapFree);

    if (context->TabHeader == NULL) {
        kdDebugPrint("Could not create tabcontrol window\r\n");
        return FALSE;
    }

    for (i = 0; i < _countof(imsTabs); i++) {
        TabAddPage(context->TabHeader,
            imsTabs[i].ResourceId,
            imsTabs[i].WndProc,
            imsTabs[i].TabCaption,
            I_IMAGENONE,
            (LPARAM)context);
    }

    TabOnSelChanged(context->TabHeader);

    // call resize
    SendMessage(context->MainWindow, WM_SIZE, 0, 0);

    do {
        rv = GetMessage(&msg1, NULL, 0, 0);

        if (rv == -1)
            break;

        TranslateMessage(&msg1);
        DispatchMessage(&msg1);

    } while (rv != 0 && InterlockedCompareExchange((PLONG)&g_pluginState, 0, 0) == PLUGIN_RUNNING);

    TabDestroyControl(context->TabHeader);
    DestroyWindow(context->MainWindow);

    return TRUE;
}

/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       UTILS.H
*
*  VERSION:     1.20
*
*  DATE:        03 Oct 2025
*
*  Common header file for the plugin support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef PLUGIN_UTILS_H
#define PLUGIN_UTILS_H

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#pragma warning(push)
#pragma warning(disable: 4005) //macro redefinition
#include <ntstatus.h>
#pragma warning(pop)

#include "ntos/ntos.h"
#include "ntos/ntsup.h"
#include <strsafe.h>

#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_

#include "minirtl/minirtl.h"
#include "tabs/tabsctrl.h"
#include "treelist/treelist.h"

#define supHeapAlloc ntsupHeapAlloc
#define supHeapFree ntsupHeapFree

#define DefaultSystemDpi            96
#define ScaleDPI(Value, CurrentDPI) MulDiv(Value, CurrentDPI, DefaultSystemDpi)

typedef struct _TL_SUBITEMS_FIXED {
    ULONG       Count;
    ULONG       ColorFlags;
    COLORREF    BgColor;
    COLORREF    FontColor;
    PVOID       UserParam;
    LPTSTR      CustomTooltip;
    LPTSTR      Text[2];
} TL_SUBITEMS_FIXED, * PTL_SUBITEMS_FIXED;

VOID supSetWaitCursor(
    _In_ BOOL fSet);

NTSTATUS supMapSection(
    _In_ HANDLE SectionHandle,
    _Out_ PVOID* BaseAddress,
    _Out_ SIZE_T* ViewSize);

BOOL supSaveDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR SaveFileName,
    _In_ LPWSTR lpDialogFilter);

BOOL supListViewExportToFile(
    _In_ LPWSTR FileName,
    _In_ HWND WindowHandle,
    _In_ HWND ListView,
    _In_ LPWSTR FileFilter);

VOID supStatusBarSetText(
    _In_ HWND hwndStatusBar,
    _In_ WPARAM partIndex,
    _In_ LPWSTR lpText);

HTREEITEM supTreeListAddItem(
    _In_ HWND TreeList,
    _In_opt_ HTREEITEM hParent,
    _In_ UINT mask,
    _In_ UINT state,
    _In_ UINT stateMask,
    _In_opt_ LPWSTR pszText,
    _In_opt_ PVOID subitems);

INT supAddListViewColumn(
    _In_ HWND ListViewHwnd,
    _In_ INT ColumnIndex,
    _In_ INT SubItemIndex,
    _In_ INT OrderIndex,
    _In_ INT ImageIndex,
    _In_ INT Format,
    _In_ LPWSTR Text,
    _In_ INT Width,
    _In_ INT DpiValue);

BOOL supListViewAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndLv,
    _In_ UINT uId,
    _In_ UINT uPos,
    _In_ POINT* lpPoint,
    _Out_ INT* pItemHit,
    _Out_ INT* pColumnHit);

LPWSTR supGetItemText(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _Out_opt_ PSIZE_T lpSize);

VOID supClipboardCopy(
    _In_ LPWSTR lpText,
    _In_ SIZE_T cbText);

BOOL supListViewCopyItemValueToClipboard(
    _In_ HWND hwndListView,
    _In_ INT iItem,
    _In_ INT iSubItem);

_Success_(return)
BOOL supFreeDuplicatedUnicodeString(
    _In_ HANDLE HeapHandle,
    _Inout_ PUNICODE_STRING DuplicatedString,
    _In_ BOOL DoZeroMemory);

_Success_(return)
BOOL supDuplicateUnicodeString(
    _In_ HANDLE HeapHandle,
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString);

BOOL supTreeListAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndTreeList,
    _In_ UINT uId,
    _In_ UINT uPos,
    _In_ LPARAM lParam,
    _In_ INT * pSubItemHit);

BOOL supGetWin32FileName(
    _In_ LPWSTR FileName,
    _Inout_ LPWSTR Win32FileName,
    _In_ SIZE_T ccWin32FileName);

INT supGetMaxCompareTwoFixedStrings(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

INT supGetMaxOfTwoU64FromHex(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

BOOL supTreeListCopyItemValueToClipboard(
    _In_ HWND hwndTreeList,
    _In_ INT tlSubItemHit);

#endif /* PLUGIN_UTILS_H */

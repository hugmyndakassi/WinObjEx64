/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       UI.H
*
*  VERSION:     1.20
*
*  DATE:        03 Oct 2025
*
*  WinObjEx64 ApiSetView UI constants, definitions and includes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")

#define DefaultSystemDpi            96
#define WINOBJEX64_ICON_MAIN        174
#define ID_OBJECT_COPY              40008

#define T_EmptyString TEXT("")

typedef struct _VALUE_DESC {
    ULONG Value;
    LPCWSTR Desc;
} VALUE_DESC, * PVALUE_DESC;

typedef struct _GUI_CONTEXT {
    HWND MainWindow;
    HWND TreeList;
    HWND SearchEdit;
    HANDLE PluginHeap;
    HANDLE WorkerThread;
    HICON WindowIcon;

    INT tlSubItemHit;

    WCHAR SchemaFileName[MAX_PATH * 2];

    //
    // WinObjEx64 data and pointers.
    //
    WINOBJEX_PARAM_BLOCK ParamBlock;
} GUI_CONTEXT, *PGUI_CONTEXT;

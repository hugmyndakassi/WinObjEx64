/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.20
*
*  DATE:        03 Oct 2025
*
*  Common header file for the Windows Object Explorer ImageScope plugin.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// Strict UNICODE
//
#if !defined UNICODE
#error ANSI build is not supported
#endif

#define OEMRESOURCE
#include <Windows.h>
#include <windowsx.h>
#include <strsafe.h>
#include <commctrl.h>
#include <Uxtheme.h>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>
#pragma warning(pop)

#pragma warning(disable: 6258) // TerminateThread
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER
#pragma warning(disable: 26812) // Prefer 'enum class' over 'enum'


#include "ntos/ntos.h"
#include "ntos/ntsup.h"
#include "treelist/treelist.h"
#include "minirtl/minirtl.h"
#include "tabs/tabsctrl.h"
#include "plugin_def.h"
#include "sdk/extdef.h"
#include "resource.h"
#include "query.h"
#include "ui.h"

//declared in main.c
extern HINSTANCE g_thisDll;
extern volatile DWORD g_pluginState;
extern WINOBJEX_PLUGIN* g_plugin;

#ifdef _DEBUG
#define kdDebugPrint(f, ...) DbgPrint(f, __VA_ARGS__)
#else
#define kdDebugPrint(f, ...) 
#endif

#include "utils.h"

/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2025
*
*  TITLE:       OBJECTS.C
*
*  VERSION:     2.10
*
*  DATE:        03 Oct 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

WOBJ_TYPE_DESC g_TypeUnknown = { OBTYPE_NAME_UNKNOWN, 0, ObjectTypeUnknown, IDI_ICON_UNKNOWN, IDS_DESC_UNKNOWN };

WOBJ_TYPE_DESC g_TypeActivationObject = { L"ActivationObject", 0xde960015, ObjectTypeActivationObject, IDI_ICON_ACTIVATIONOBJECT, IDS_DESC_ACTIVATIONOBJECT };
WOBJ_TYPE_DESC g_TypeActivityReference = { L"ActivityReference", 0x44db295c, ObjectTypeActivityReference, IDI_ICON_ACTIVITYREFERENCE, IDS_DESC_ACTIVITYREFERENCE };
WOBJ_TYPE_DESC g_TypeAdapter = { L"Adapter", 0x5b4bfe0f, ObjectTypeAdapter, IDI_ICON_ADAPTER, IDS_DESC_ADAPTER };
WOBJ_TYPE_DESC g_TypeALPCPort = { L"ALPC Port", 0xfc99f003, ObjectTypePort, IDI_ICON_PORT, IDS_DESC_PORT };
WOBJ_TYPE_DESC g_TypeCallback = { L"Callback", 0xd619e0a5, ObjectTypeCallback, IDI_ICON_CALLBACK, IDS_DESC_CALLBACK };
WOBJ_TYPE_DESC g_TypeComposition = { L"Composition", 0xf009caea, ObjectTypeComposition, IDI_ICON_DXOBJECT, IDS_DESC_COMPOSITION };
WOBJ_TYPE_DESC g_TypeController = { L"Controller", 0x38a0df3c, ObjectTypeController, IDI_ICON_CONTROLLER, IDS_DESC_CONTROLLER };
WOBJ_TYPE_DESC g_TypeCoreMessaging = { L"CoreMessaging", 0x86bcebe5, ObjectTypeCoreMessaging, IDI_ICON_COREMESSAGING, IDS_DESC_COREMESSAGING };
WOBJ_TYPE_DESC g_TypeCoverageSampler = { L"CoverageSampler", 0xb6a0f960, ObjectTypeCoverageSampler, IDI_ICON_COVERAGESAMPLER, IDS_DESC_COVERAGESAMPLER };
WOBJ_TYPE_DESC g_TypeCpuPartition = { L"CpuPartition", 0xafdf1c82, ObjectTypeCpuPartition, IDI_ICON_CPUPARTITION, IDS_DESC_CPUPARTITION };
WOBJ_TYPE_DESC g_TypeCrossVmEvent = { L"CrossVmEvent", 0x6eb9ebe3, ObjectTypeCrossVmEvent, IDI_ICON_CROSSVMEVENT, IDS_DESC_CROSSVMEVENT };
WOBJ_TYPE_DESC g_TypeCrossVmMutant = { L"CrossVmMutant", 0x4c942872, ObjectTypeCrossVmMutant, IDI_ICON_CROSSVMMUTANT, IDS_DESC_CROSSVMMUTANT };
WOBJ_TYPE_DESC g_TypeDebugObject = { L"DebugObject", 0x8282e52, ObjectTypeDebugObject, IDI_ICON_DEBUGOBJECT, IDS_DESC_DEBUGOBJECT };
WOBJ_TYPE_DESC g_TypeDesktop = { OBTYPE_NAME_DESKTOP, 0xd1ffc79c, ObjectTypeDesktop, IDI_ICON_DESKTOP, IDS_DESC_DESKTOP };
WOBJ_TYPE_DESC g_TypeDevice = { L"Device", OBTYPE_HASH_DEVICE, ObjectTypeDevice, IDI_ICON_DEVICE, IDS_DESC_DEVICE };
WOBJ_TYPE_DESC g_TypeDirectory = { OBTYPE_NAME_DIRECTORY, OBTYPE_HASH_DIRECTORY, ObjectTypeDirectory, IDI_ICON_DIRECTORY, IDS_DESC_DIRECTORY };
WOBJ_TYPE_DESC g_TypeDmaAdapter = { L"DmaAdapter", 0x2201d697, ObjectTypeDmaAdapter, IDI_ICON_HALDMA, IDS_DESC_DMAADAPTER };
WOBJ_TYPE_DESC g_TypeDmaDomain = { L"DmaDomain", 0xfe7e671c, ObjectTypeDmaDomain, IDI_ICON_HALDMA, IDS_DESC_DMADOMAIN };
WOBJ_TYPE_DESC g_TypeDriver = { L"Driver", OBTYPE_HASH_DRIVER, ObjectTypeDriver, IDI_ICON_DRIVER, IDS_DESC_DRIVER };
WOBJ_TYPE_DESC g_TypeDxgkCompositionObject = { L"DxgkCompositionObject", 0xf2bf1f91, ObjectTypeDxgkComposition, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_COMPOSITION_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkCurrentDxgProcessObject = { L"DxgkCurrentDxgProcessObject", 0xc27e9d7c, ObjectTypeDxgkCurrentDxgProcessObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_CURRENT_DXG_PROCESS_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkCurrentDxgThreadObject = { L"DxgkCurrentDxgThreadObject", 0xc8d07f5b, ObjectTypeDxgkCurrentDxgThreadObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_CURRENT_DXG_THREAD_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkDisplayManagerObject = { L"DxgkDisplayManagerObject", 0x5afc4062, ObjectTypeDxgkDisplayManager, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_DISPLAY_MANAGER_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkDisplayMuxSwitch = { L"DxgkDisplayMuxSwitch", 0x180e2a1a, ObjectTypeDxgkDisplayMuxSwitch, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_DISPLAYMUXSWITCH };
WOBJ_TYPE_DESC g_TypeDxgkSharedBundleObject = { L"DxgkSharedBundleObject", 0xf7e4ab9e, ObjectTypeDxgkSharedBundle, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_BUNDLE_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkSharedKeyedMutexObject = { L"DxgkSharedKeyedMutexObject", 0xd6c628fd, ObjectTypeDxgkSharedKeyedMutex, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_KEYED_MUTEX_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkSharedProtectedSessionObject = { L"DxgkSharedProtectedSessionObject", 0xa9676f44, ObjectTypeDxgkSharedProtectedSession, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_PROTECTED_SESSION_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkSharedResource = { L"DxgkSharedResource", 0x632e6c2b, ObjectTypeDxgkSharedResource, IDI_ICON_DXOBJECT, IDS_DESC_DXGKSHAREDRES };
WOBJ_TYPE_DESC g_TypeDxgkSharedSwapChainObject = { L"DxgkSharedSwapChainObject", 0xf5053210, ObjectTypeDxgkSharedSwapChain, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_SWAPCHAIN };
WOBJ_TYPE_DESC g_TypeDxgkSharedSyncObject = { L"DxgkSharedSyncObject", 0xa29968d7, ObjectTypeDxgkSharedSyncObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_SYNC };
WOBJ_TYPE_DESC g_TypeEnergyTracker = { L"EnergyTracker", 0x4dcec6d0, ObjectTypeEnergyTracker, IDI_ICON_ENERGYTRACKER, IDS_DESC_ENERGYTRACKER };
WOBJ_TYPE_DESC g_TypeEtwConsumer = { L"EtwConsumer", 0x31a53abe, ObjectTypeETWConsumer, IDI_ICON_ETWCONSUMER, IDS_DESC_ETWCONSUMER };
WOBJ_TYPE_DESC g_TypeEtwRegistration = { L"EtwRegistration", 0x89b06481, ObjectTypeETWRegistration, IDI_ICON_ETWREGISTRATION, IDS_DESC_ETWREGISTRATION };
WOBJ_TYPE_DESC g_TypeEtwSessionDemuxEntry = { L"EtwSessionDemuxEntry", 0x4ce2d111, ObjectTypeEtwSessionDemuxEntry, IDI_ICON_ETWSESSIONDEMUXENTRY, IDS_DESC_ETWSESSIONDEMUXENTRY };
WOBJ_TYPE_DESC g_TypeEvent = { L"Event", 0xf3040cba, ObjectTypeEvent, IDI_ICON_EVENT, IDS_DESC_EVENT };
WOBJ_TYPE_DESC g_TypeEventPair = { L"EventPair", 0x97834894, ObjectTypeEventPair, IDI_ICON_EVENTPAIR, IDS_DESC_EVENTPAIR };
WOBJ_TYPE_DESC g_TypeFile = { OBTYPE_NAME_FILE, 0xecfd8b1c, ObjectTypeFile, IDI_ICON_FILE, IDS_DESC_FILE };
WOBJ_TYPE_DESC g_TypeFilterCommunicationPort = { L"FilterCommunicationPort", 0x7849195f, ObjectTypeFltComnPort, IDI_ICON_FLTCOMMPORT, IDS_DESC_FLT_COMM_PORT };
WOBJ_TYPE_DESC g_TypeFilterConnectionPort = { L"FilterConnectionPort", 0x4598bf7, ObjectTypeFltConnPort, IDI_ICON_FLTCONNPORT, IDS_DESC_FLT_CONN_PORT };
WOBJ_TYPE_DESC g_TypeIoCompletion = { L"IoCompletion", 0xbc81c342, ObjectTypeIoCompletion, IDI_ICON_IOCOMPLETION, IDS_DESC_IOCOMPLETION };
WOBJ_TYPE_DESC g_TypeIoCompletionReserve = { L"IoCompletionReserve", 0xca6e211a, ObjectTypeIoCompletionReserve, IDI_ICON_IOCOMPLETION, IDS_DESC_IOCOMPLETIONRESERVE };
WOBJ_TYPE_DESC g_TypeIoRing = { L"IoRing", 0xe17640f6, ObjectTypeIoRing, IDI_ICON_IORING, IDS_DESC_IORING };
WOBJ_TYPE_DESC g_TypeIRTimer = { L"IRTimer", 0xc161a6dc, ObjectTypeIRTimer, IDI_ICON_IRTIMER, IDS_DESC_IRTIMER };
WOBJ_TYPE_DESC g_TypeJob = { L"Job", 0x24df96fd, ObjectTypeJob, IDI_ICON_JOB, IDS_DESC_JOB };
WOBJ_TYPE_DESC g_TypeKey = { L"Key", 0x2553a41f, ObjectTypeKey, IDI_ICON_KEY, IDS_DESC_KEY };
WOBJ_TYPE_DESC g_TypeKeyedEvent = { L"KeyedEvent", 0x6c3a045c, ObjectTypeKeyedEvent, IDI_ICON_KEYEDEVENT, IDS_DESC_KEYEDEVENT };
WOBJ_TYPE_DESC g_TypeMutant = { L"Mutant", 0xfba93d5b, ObjectTypeMutant, IDI_ICON_MUTANT, IDS_DESC_MUTANT };
WOBJ_TYPE_DESC g_TypeNdisCmState = { L"NdisCmState", 0x28077967, ObjectTypeNdisCmState, IDI_ICON_NDISCMSTATE, IDS_DESC_NDISCMSTATE };
WOBJ_TYPE_DESC g_TypePartition = { L"Partition", 0x5227054a, ObjectTypeMemoryPartition, IDI_ICON_MEMORYPARTITION, IDS_DESC_MEMORY_PARTITION };
WOBJ_TYPE_DESC g_TypePcwObject = { L"PcwObject", 0xe3f801c3, ObjectTypePcwObject, IDI_ICON_PCWOBJECT, IDS_DESC_PCWOBJECT };
WOBJ_TYPE_DESC g_TypePowerRequest = { L"PowerRequest", 0xb5a1b3ea, ObjectTypePowerRequest, IDI_ICON_POWERREQUEST, IDS_DESC_POWERREQUEST };
WOBJ_TYPE_DESC g_TypeProcess = { OBTYPE_NAME_PROCESS, 0x70fcfc4f, ObjectTypeProcess, IDI_ICON_PROCESS, IDS_DESC_PROCESS };
WOBJ_TYPE_DESC g_TypeProcessStateChange = { L"ProcessStateChange", 0x6fd57b92, ObjectTypeProcessStateChange, IDI_ICON_PROCESSSTATECHANGE, IDS_DESC_PROCESSSTATECHANGE };
WOBJ_TYPE_DESC g_TypeProfile = { L"Profile", 0xfe82aac9, ObjectTypeProfile, IDI_ICON_PROFILE, IDS_DESC_PROFILE };
WOBJ_TYPE_DESC g_TypePsSiloContextNonPaged = { L"PsSiloContextNonPaged", 0xe2c391fb, ObjectTypePsSiloContextNonPaged, IDI_ICON_PSSILOCONTEXT, IDS_DESC_PSSILOCONTEXTNP };
WOBJ_TYPE_DESC g_TypePsSiloContextPaged = { L"PsSiloContextPaged", 0x8f91f0a2, ObjectTypePsSiloContextPaged, IDI_ICON_PSSILOCONTEXT, IDS_DESC_PSSILOCONTEXT };
WOBJ_TYPE_DESC g_TypeRawInputManager = { L"RawInputManager", 0xf28870cb, ObjectTypeRawInputManager, IDI_ICON_RAWINPUTMANAGER, IDS_DESC_RAWINPUTMANAGER };
WOBJ_TYPE_DESC g_TypeRegistryTransaction = { L"RegistryTransaction", 0xba530c61, ObjectTypeRegistryTransaction, IDI_ICON_KEY, IDS_DESC_REGISTRY_TRANSACTION };
WOBJ_TYPE_DESC g_TypeSchedulerSharedData = { L"SchedulerSharedData", 0xa4930ca, ObjectTypeSchedulerSharedData, IDI_ICON_SCHEDULERSHAREDDATA, IDS_DESC_SCHEDULERSHAREDDATA };
WOBJ_TYPE_DESC g_TypeSection = { L"Section", OBTYPE_HASH_SECTION, ObjectTypeSection, IDI_ICON_SECTION, IDS_DESC_SECTION };
WOBJ_TYPE_DESC g_TypeSemaphore = { L"Semaphore", 0x33b553e4, ObjectTypeSemaphore, IDI_ICON_SEMAPHORE, IDS_DESC_SEMAPHORE };
WOBJ_TYPE_DESC g_TypeSession = { L"Session", 0xcd4f9c96, ObjectTypeSession, IDI_ICON_SESSION, IDS_DESC_SESSION };
WOBJ_TYPE_DESC g_TypeSymbolicLink = { L"SymbolicLink", OBTYPE_HASH_SYMBOLIC_LINK, ObjectTypeSymbolicLink, IDI_ICON_SYMLINK, IDS_DESC_SYMLINK };
WOBJ_TYPE_DESC g_TypeTerminal = { L"Terminal", 0x17fd8d1c, ObjectTypeTerminal, IDI_ICON_TERMINAL, IDS_DESC_TERMINAL };
WOBJ_TYPE_DESC g_TypeTerminalEventQueue = { L"TerminalEventQueue", 0x87c5d493, ObjectTypeTerminalEventQueue, IDI_ICON_TERMINALEVENTQUEUE, IDS_DESC_TERMINALEVENTQUEUE };
WOBJ_TYPE_DESC g_TypeThread = { OBTYPE_NAME_THREAD, 0xc8bcac4a, ObjectTypeThread, IDI_ICON_THREAD, IDS_DESC_THREAD };
WOBJ_TYPE_DESC g_TypeThreadStateChange = { L"ThreadStateChange", 0x88afedd7, ObjectTypeThreadStateChange, IDI_ICON_THREADSTATECHANGE, IDS_DESC_THREADSTATECHANGE };
WOBJ_TYPE_DESC g_TypeTimer = { L"Timer", 0x94ec7de5, ObjectTypeTimer, IDI_ICON_TIMER, IDS_DESC_TIMER };
WOBJ_TYPE_DESC g_TypeTmEn = { L"TmEn", 0x7a2e2a02, ObjectTypeTmEn, IDI_ICON_TMEN, IDS_DESC_TMEN };
WOBJ_TYPE_DESC g_TypeTmRm = { L"TmRm", 0x7a3b2d34, ObjectTypeTmRm, IDI_ICON_TMRM, IDS_DESC_TMRM };
WOBJ_TYPE_DESC g_TypeTmTm = { L"TmTm", 0x7a3d2db2, ObjectTypeTmTm, IDI_ICON_TMTM, IDS_DESC_TMTM };
WOBJ_TYPE_DESC g_TypeTmTx = { L"TmTx", 0x7a3d2dbd, ObjectTypeTmTx, IDI_ICON_TMTX, IDS_DESC_TMTX };
WOBJ_TYPE_DESC g_TypeToken = { OBTYPE_NAME_TOKEN, 0xab194359, ObjectTypeToken, IDI_ICON_TOKEN, IDS_DESC_TOKEN };
WOBJ_TYPE_DESC g_TypeTpWorkerFactory = { L"TpWorkerFactory", 0x84a8cd0, ObjectTypeTpWorkerFactory, IDI_ICON_TPWORKERFACTORY,IDS_DESC_TPWORKERFACTORY };
WOBJ_TYPE_DESC g_TypeType = { L"Type", OBTYPE_HASH_TYPE, ObjectTypeType, IDI_ICON_TYPE, IDS_DESC_TYPE };
WOBJ_TYPE_DESC g_TypeUserApcReserve = { L"UserApcReserve", 0xa3fa2453, ObjectTypeUserApcReserve, IDI_ICON_USERAPCRESERVE, IDS_DESC_USERAPCRESERVE };
WOBJ_TYPE_DESC g_TypeVirtualKey = { L"VirtualKey", 0x77158ef4, ObjectTypeVirtualKey, IDI_ICON_VIRTUALKEY, IDS_DESC_VIRTUALKEY };
WOBJ_TYPE_DESC g_TypeVRegConfigurationContext = { L"VRegConfigurationContext", 0x783eeab7, ObjectTypeVRegConfigurationContext, IDI_ICON_VREGCFGCTX, IDS_DESC_VREGCFGCTX };
WOBJ_TYPE_DESC g_TypeWaitablePort = { L"WaitablePort", 0x66debaf0, ObjectTypeWaitablePort, IDI_ICON_WAITABLEPORT, IDS_DESC_WAITABLEPORT };
WOBJ_TYPE_DESC g_TypeWaitCompletionPacket = { L"WaitCompletionPacket", 0xdaa80e19, ObjectTypeWaitCompletionPacket, IDI_ICON_WAITCOMPLETIONPACKET, IDS_DESC_WAITCOMPLETIONPACKET };
WOBJ_TYPE_DESC g_TypeWinstation = { L"WindowStation", OBTYPE_HASH_WINSTATION, ObjectTypeWinstation, IDI_ICON_WINSTATION, IDS_DESC_WINSTATION };
WOBJ_TYPE_DESC g_TypeWmiGuid = { L"WmiGuid", 0x36d9823c, ObjectTypeWMIGuid, IDI_ICON_WMIGUID, IDS_DESC_WMIGUID };

// Maximum object type index value for lookup table sizing
#define MAX_OBJECT_TYPE_INDEX    ObjectTypeUnknown

#define OBJECT_TYPE_ENTRIES \
    X(g_TypeActivationObject) \
    X(g_TypeActivityReference) \
    X(g_TypeAdapter) \
    X(g_TypeALPCPort) \
    X(g_TypeCallback) \
    X(g_TypeComposition) \
    X(g_TypeController) \
    X(g_TypeCoreMessaging) \
    X(g_TypeCoverageSampler) \
    X(g_TypeCpuPartition) \
    X(g_TypeCrossVmEvent) \
    X(g_TypeCrossVmMutant) \
    X(g_TypeDebugObject) \
    X(g_TypeDesktop) \
    X(g_TypeDevice) \
    X(g_TypeDirectory) \
    X(g_TypeDmaAdapter) \
    X(g_TypeDmaDomain) \
    X(g_TypeDriver) \
    X(g_TypeDxgkCompositionObject) \
    X(g_TypeDxgkCurrentDxgProcessObject) \
    X(g_TypeDxgkCurrentDxgThreadObject) \
    X(g_TypeDxgkDisplayManagerObject) \
    X(g_TypeDxgkDisplayMuxSwitch) \
    X(g_TypeDxgkSharedBundleObject) \
    X(g_TypeDxgkSharedKeyedMutexObject) \
    X(g_TypeDxgkSharedProtectedSessionObject) \
    X(g_TypeDxgkSharedResource) \
    X(g_TypeDxgkSharedSwapChainObject) \
    X(g_TypeDxgkSharedSyncObject) \
    X(g_TypeEnergyTracker) \
    X(g_TypeEtwConsumer) \
    X(g_TypeEtwRegistration) \
    X(g_TypeEtwSessionDemuxEntry) \
    X(g_TypeEvent) \
    X(g_TypeEventPair) \
    X(g_TypeFile) \
    X(g_TypeFilterCommunicationPort) \
    X(g_TypeFilterConnectionPort) \
    X(g_TypeIoCompletion) \
    X(g_TypeIoCompletionReserve) \
    X(g_TypeIoRing) \
    X(g_TypeIRTimer) \
    X(g_TypeJob) \
    X(g_TypeKey) \
    X(g_TypeKeyedEvent) \
    X(g_TypeMutant) \
    X(g_TypeNdisCmState) \
    X(g_TypePartition) \
    X(g_TypePcwObject) \
    X(g_TypePowerRequest) \
    X(g_TypeProcess) \
    X(g_TypeProcessStateChange) \
    X(g_TypeProfile) \
    X(g_TypePsSiloContextNonPaged) \
    X(g_TypePsSiloContextPaged) \
    X(g_TypeRawInputManager) \
    X(g_TypeRegistryTransaction) \
    X(g_TypeSchedulerSharedData) \
    X(g_TypeSection) \
    X(g_TypeSemaphore) \
    X(g_TypeSession) \
    X(g_TypeSymbolicLink) \
    X(g_TypeTerminal) \
    X(g_TypeTerminalEventQueue) \
    X(g_TypeThread) \
    X(g_TypeThreadStateChange) \
    X(g_TypeTimer) \
    X(g_TypeTmEn) \
    X(g_TypeTmRm) \
    X(g_TypeTmTm) \
    X(g_TypeTmTx) \
    X(g_TypeToken) \
    X(g_TypeTpWorkerFactory) \
    X(g_TypeType) \
    X(g_TypeUserApcReserve) \
    X(g_TypeVirtualKey) \
    X(g_TypeVRegConfigurationContext) \
    X(g_TypeWaitablePort) \
    X(g_TypeWaitCompletionPacket) \
    X(g_TypeWinstation) \
    X(g_TypeWmiGuid)

//
// Array items must be always sorted by object type name.
//
static WOBJ_TYPE_DESC* gpObjectTypes[] = {
#define X(type) &type,
    OBJECT_TYPE_ENTRIES
#undef X
};

//
// Number of items in gpObjectTypes array
//
ULONG g_ObjectTypesCount = RTL_NUMBER_OF(gpObjectTypes);

// Lookup table for access by type index
static WOBJ_TYPE_DESC* g_TypeIndexLookup[MAX_OBJECT_TYPE_INDEX + 1];

// Hash table for type names
typedef struct _OBTYPE_HASH_ENTRY {
    ULONG NameHash;
    WOBJ_TYPE_DESC* TypeDesc;
} OBTYPE_HASH_ENTRY, * POBTYPE_HASH_ENTRY;

// Hashtable for types
#define HASH_TABLE_SIZE 256
static OBTYPE_HASH_ENTRY g_TypeHashTable[HASH_TABLE_SIZE];

// One-time init
static INIT_ONCE g_LookupTablesInitOnce = INIT_ONCE_STATIC_INIT;

/*
* ObManagerComparerName
*
* Purpose:
*
* Support comparer routine to work with objects array.
*
*/
INT ObManagerComparerName(
    _In_ PCVOID FirstObject,
    _In_ PCVOID SecondObject
)
{
    WOBJ_TYPE_DESC* firstObject = (WOBJ_TYPE_DESC*)FirstObject;
    WOBJ_TYPE_DESC* secondObject = *(WOBJ_TYPE_DESC**)SecondObject;

    return (_strcmpi(firstObject->Name, secondObject->Name));
}

/*
* ObManagerInitOnceCallback
*
* Purpose:
*
* Initialize lookup tables for faster object type searching.
*
*/
BOOL CALLBACK ObManagerInitOnceCallback(
    _Inout_ PINIT_ONCE InitOnce,
    _Inout_opt_ PVOID Parameter,
    _Out_opt_ PVOID* Context
)
{
    ULONG i, k;
    ULONG hashIndex;
    WOBJ_OBJECT_TYPE typeIndex;

    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);

    RtlSecureZeroMemory(g_TypeIndexLookup, sizeof(g_TypeIndexLookup));
    RtlSecureZeroMemory(g_TypeHashTable, sizeof(g_TypeHashTable));

#if _DEBUG
    // Verify gpObjectTypes is sorted (case-insensitive)
    if (g_ObjectTypesCount > 1) {
        for (k = 1; k < g_ObjectTypesCount; k++) {
            if (_strcmpi(gpObjectTypes[k - 1]->Name, gpObjectTypes[k]->Name) > 0) {
                kdDebugPrint("gpObjectTypes ordering error at %lu: %ws > %ws\r\n",
                    k, gpObjectTypes[k - 1]->Name, gpObjectTypes[k]->Name);
                break;
            }
        }
    }
#endif

    // Fill lookup tables
    for (i = 0; i < g_ObjectTypesCount; i++) {

        typeIndex = gpObjectTypes[i]->Index;
        if (typeIndex >= 0 && (ULONG)typeIndex <= MAX_OBJECT_TYPE_INDEX) {
            g_TypeIndexLookup[typeIndex] = gpObjectTypes[i];
        }
#if _DEBUG
        else {
            kdDebugPrint("Type index out of bounds for %ws (%lu)\r\n",
                gpObjectTypes[i]->Name, (ULONG)typeIndex);
        }
#endif

        if (gpObjectTypes[i]->NameHash != 0) {
            hashIndex = gpObjectTypes[i]->NameHash & (HASH_TABLE_SIZE - 1);
            g_TypeHashTable[hashIndex].NameHash = gpObjectTypes[i]->NameHash;
            g_TypeHashTable[hashIndex].TypeDesc = gpObjectTypes[i];
        }
    }

    if (Context) *Context = (PVOID)1;
    return TRUE;
}

/*
* ObManagerEnsureInitialized
*
* Purpose:
*
* Ensure lookup tables are initialized exactly once.
*
*/
VOID ObManagerEnsureInitialized(
    VOID
)
{
    InitOnceExecuteOnce(&g_LookupTablesInitOnce, ObManagerInitOnceCallback, NULL, NULL);
}

/*
* ObManagerInitLookupTables
*
* Purpose:
*
* Initialize lookup tables for faster object type searching.
*
*/
VOID ObManagerInitLookupTables(VOID)
{
    ObManagerEnsureInitialized();
}

/*
* ObManagerGetNameByIndex
*
* Purpose:
*
* Returns object name by index of known type.
*
*/
LPWSTR ObManagerGetNameByIndex(
    _In_ WOBJ_OBJECT_TYPE TypeIndex
)
{
    ObManagerEnsureInitialized();

    if (TypeIndex >= 0 && (ULONG)TypeIndex <= MAX_OBJECT_TYPE_INDEX &&
        g_TypeIndexLookup[TypeIndex] != NULL)
    {
        return g_TypeIndexLookup[TypeIndex]->Name;
    }

    return OBTYPE_NAME_UNKNOWN;
}

/*
* ObManagerGetEntryByTypeIndex
*
* Purpose:
*
* Returns object entry by type index.
*
*/
WOBJ_TYPE_DESC* ObManagerGetEntryByTypeIndex(
    _In_ WOBJ_OBJECT_TYPE TypeIndex
)
{
    ObManagerEnsureInitialized();

    if (TypeIndex >= 0 && (ULONG)TypeIndex <= MAX_OBJECT_TYPE_INDEX &&
        g_TypeIndexLookup[TypeIndex] != NULL)
    {
        return g_TypeIndexLookup[TypeIndex];
    }

    return &g_TypeUnknown;
}

/*
* ObManagerLookupByHash
*
* Purpose:
*
* Fast lookup by hash value.
*
*/
WOBJ_TYPE_DESC* ObManagerLookupByHash(
    _In_ ULONG NameHash
)
{
    ULONG hashIndex;

    if (NameHash == 0)
        return NULL;

    hashIndex = NameHash & (HASH_TABLE_SIZE - 1);

    if (g_TypeHashTable[hashIndex].NameHash == NameHash)
        return g_TypeHashTable[hashIndex].TypeDesc;

    return NULL;
}

/*
* ObManagerGetEntryByTypeName
*
* Purpose:
*
* Returns object description entry by type name or g_TypeUnknown if none found.
*
*/
WOBJ_TYPE_DESC* ObManagerGetEntryByTypeName(
    _In_opt_ LPCWSTR lpTypeName
)
{
    WOBJ_TYPE_DESC searchItem;
    WOBJ_TYPE_DESC* result;
    PVOID lookupItem;
    ULONG nameHash;

    if (lpTypeName == NULL) {
        return &g_TypeUnknown;
    }

    ObManagerEnsureInitialized();

    // Try fast lookup by hash first
    nameHash = supHashString(lpTypeName, (ULONG)_strlen(lpTypeName));
    result = ObManagerLookupByHash(nameHash);
    if (result != NULL) {
        // Verify name matches (in case of hash collision)
        if (_strcmpi(result->Name, lpTypeName) == 0)
            return result;
    }

    // Fall back to binary search
    searchItem.Name = (LPWSTR)lpTypeName;

    lookupItem = supBSearch((PCVOID)&searchItem,
        (PCVOID)gpObjectTypes,
        g_ObjectTypesCount,
        sizeof(PVOID),
        ObManagerComparerName);

    if (lookupItem == NULL) {
        result = &g_TypeUnknown;
    }
    else {
        result = *(WOBJ_TYPE_DESC**)lookupItem;
    }

    return result;
}

/*
* ObManagerGetIndexByTypeName
*
* Purpose:
*
* Returns object index of known type.
*
*/
WOBJ_OBJECT_TYPE ObManagerGetIndexByTypeName(
    _In_opt_ LPCWSTR lpTypeName
)
{
    WOBJ_TYPE_DESC* lookupItem = ObManagerGetEntryByTypeName(lpTypeName);

    return lookupItem->Index;
}

/*
* ObManagerGetImageIndexByTypeName
*
* Purpose:
*
* Returns object image index of known type.
*
*/
INT ObManagerGetImageIndexByTypeName(
    _In_opt_ LPCWSTR lpTypeName
)
{
    WOBJ_TYPE_DESC* lookupItem = ObManagerGetEntryByTypeName(lpTypeName);

    return lookupItem->ImageIndex;
}

/*
* ObManagerLoadImageForType
*
* Purpose:
*
* Load image of the given id.
*
*/
INT ObManagerLoadImageForType(
    _In_ HIMAGELIST ImageList,
    _In_ INT ResourceImageId
)
{
    INT ImageIndex = I_IMAGENONE;
    HICON hIcon;

    hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(ResourceImageId),
        IMAGE_ICON,
        16,
        16,
        LR_DEFAULTCOLOR);

    if (hIcon) {
        ImageIndex = ImageList_ReplaceIcon(ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    return ImageIndex;
}

/*
* ObManagerLoadImageList
*
* Purpose:
*
* Create and load image list from icon resource type.
*
*/
HIMAGELIST ObManagerLoadImageList(
    VOID
)
{
    UINT i;
    HIMAGELIST ImageList;
    HICON hIcon;

    ObManagerEnsureInitialized();

    ImageList = ImageList_Create(
        16,
        16,
        ILC_COLOR32 | ILC_MASK,
        g_ObjectTypesCount,
        8);

    if (!ImageList)
        return NULL;

    for (i = 0; i < g_ObjectTypesCount; i++) {
        hIcon = (HICON)LoadImage(g_WinObj.hInstance,
            MAKEINTRESOURCE(gpObjectTypes[i]->ResourceImageId),
            IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

        if (hIcon) {
            gpObjectTypes[i]->ImageIndex = ImageList_AddIcon(ImageList, hIcon);
            DestroyIcon(hIcon);
        }
        else {
            gpObjectTypes[i]->ImageIndex = I_IMAGENONE;
        }
    }

    // Load the unknown type icon
    g_TypeUnknown.ImageIndex = ObManagerLoadImageForType(ImageList,
        g_TypeUnknown.ResourceImageId);

    return ImageList;
}

PVOID ObManagerTable()
{
    return (PVOID)gpObjectTypes;
}

VOID ObManagerTest()
{
    ULONG hashValue;

    UINT i;

    for (i = 0; i < g_ObjectTypesCount; i++)
        kdDebugPrint("%ws\r\n", gpObjectTypes[i]->Name);

    for (i = 0; i < g_ObjectTypesCount; i++) {

        hashValue = supHashString(gpObjectTypes[i]->Name, (ULONG)_strlen(gpObjectTypes[i]->Name));
        kdDebugPrint("%ws = 0x%lx\r\n", gpObjectTypes[i]->Name, hashValue);
        if (hashValue != gpObjectTypes[i]->NameHash)
            MessageBox(GetDesktopWindow(), L"Wrong type hash", gpObjectTypes[i]->Name, MB_OK);

    }
}

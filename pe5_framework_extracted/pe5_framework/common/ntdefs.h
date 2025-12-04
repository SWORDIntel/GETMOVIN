/**
 * Windows NT Kernel Structure Definitions
 * 
 * RECONSTRUCTED FROM SECURITY ANALYSIS
 * Classification: TLP:RED - Security Research Only
 * 
 * Complete kernel structure definitions for Windows 10/11 x64.
 * These structures are used for privilege escalation exploit.
 * 
 * Sources:
 * - Windows Internals 7th Edition
 * - ReactOS Source Code
 * - Microsoft Debugging Symbols (ntoskrnl.pdb)
 * - PE5 Forensic Analysis Documents
 */

#ifndef NTDEFS_H
#define NTDEFS_H

#include <windows.h>

#pragma warning(disable: 4201)  // nameless struct/union
#pragma warning(disable: 4214)  // bit field types other than int

//=============================================================================
// BASIC NT TYPES
//=============================================================================

typedef LONG NTSTATUS;
typedef LONG KPRIORITY;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE  UniqueProcess;
    HANDLE  UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

//=============================================================================
// SECURITY IDENTIFIERS (SID)
//=============================================================================

typedef struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
    BYTE                        Revision;
    BYTE                        SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY    IdentifierAuthority;
    DWORD                       SubAuthority[1];  // Variable length
} SID, *PSID;

typedef struct _SID_AND_ATTRIBUTES {
    PSID    Sid;
    DWORD   Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef struct _SID_AND_ATTRIBUTES_HASH {
    DWORD                   SidCount;
    PSID_AND_ATTRIBUTES     SidAttr;
    ULONG_PTR               Hash[32];
} SID_AND_ATTRIBUTES_HASH, *PSID_AND_ATTRIBUTES_HASH;

//=============================================================================
// ACCESS CONTROL LIST (ACL)
//=============================================================================

typedef struct _ACL {
    BYTE    AclRevision;
    BYTE    Sbz1;
    WORD    AclSize;
    WORD    AceCount;
    WORD    Sbz2;
} ACL, *PACL;

//=============================================================================
// LUID - LOCALLY UNIQUE IDENTIFIER
//=============================================================================

typedef struct _LUID {
    DWORD   LowPart;
    LONG    HighPart;
} LUID, *PLUID;

typedef struct _LUID_AND_ATTRIBUTES {
    LUID    Luid;
    DWORD   Attributes;
} LUID_AND_ATTRIBUTES, *PLUID_AND_ATTRIBUTES;

//=============================================================================
// TOKEN SOURCE
//=============================================================================

#define TOKEN_SOURCE_LENGTH 8

typedef struct _TOKEN_SOURCE {
    CHAR    SourceName[TOKEN_SOURCE_LENGTH];
    LUID    SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

//=============================================================================
// SEP_TOKEN_PRIVILEGES - Token Privilege Bitmasks
//=============================================================================

typedef struct _SEP_TOKEN_PRIVILEGES {
    ULONGLONG   Present;            // +0x00: Privileges that exist on token
    ULONGLONG   Enabled;            // +0x08: Privileges currently enabled
    ULONGLONG   EnabledByDefault;   // +0x10: Privileges enabled by default
} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;

//=============================================================================
// SEP_AUDIT_POLICY - Token Audit Policy
//=============================================================================

typedef struct _SEP_AUDIT_POLICY {
    TOKEN_SOURCE    PolicyElements;
    BYTE            PolicyOverlay[32];
} SEP_AUDIT_POLICY, *PSEP_AUDIT_POLICY;

//=============================================================================
// TOKEN_TYPE
//=============================================================================

typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation = 2
} TOKEN_TYPE, *PTOKEN_TYPE;

//=============================================================================
// SECURITY_IMPERSONATION_LEVEL
//=============================================================================

typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;

//=============================================================================
// EX_PUSH_LOCK - Executive Push Lock
//=============================================================================

typedef struct _EX_PUSH_LOCK {
    union {
        struct {
            ULONG_PTR   Locked          : 1;
            ULONG_PTR   Waiting         : 1;
            ULONG_PTR   Waking          : 1;
            ULONG_PTR   MultipleShared  : 1;
            ULONG_PTR   Shared          : sizeof(ULONG_PTR) * 8 - 4;
        };
        ULONG_PTR   Value;
        PVOID       Ptr;
    };
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

//=============================================================================
// EX_FAST_REF - Executive Fast Reference
//=============================================================================

typedef struct _EX_FAST_REF {
    union {
        PVOID       Object;
        ULONG_PTR   RefCnt  : 4;
        ULONG_PTR   Value;
    };
} EX_FAST_REF, *PEX_FAST_REF;

//=============================================================================
// SEP_LOGON_SESSION_REFERENCES
//=============================================================================

typedef struct _SEP_LOGON_SESSION_REFERENCES {
    struct _SEP_LOGON_SESSION_REFERENCES*   Next;
    LUID                                    LogonId;
    LUID                                    BuddyLogonId;
    ULONG_PTR                               ReferenceCount;
    ULONG                                   Flags;
    PVOID                                   pDeviceMap;
    PVOID                                   Token;
    UNICODE_STRING                          AccountName;
    UNICODE_STRING                          AuthorityName;
    UNICODE_STRING                          ProfilePath;
} SEP_LOGON_SESSION_REFERENCES, *PSEP_LOGON_SESSION_REFERENCES;

//=============================================================================
// AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
//=============================================================================

typedef struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION {
    ULONG   AttributeCount;
    LIST_ENTRY  AttributesList;
    ULONG   WorkingAttributeCount;
    LIST_ENTRY  WorkingAttributesList;
} AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION, *PAUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION;

//=============================================================================
// TOKEN - Complete Windows Kernel Token Structure
// Windows 10 22H2 / Windows 11 (Build 19041+)
//=============================================================================

typedef struct _TOKEN {
    //=========================================================================
    // +0x000 - Token Source (16 bytes)
    //=========================================================================
    TOKEN_SOURCE                TokenSource;
    
    //=========================================================================
    // +0x010 - Token Identification (24 bytes)
    //=========================================================================
    LUID                        TokenId;                    // +0x010
    LUID                        AuthenticationId;           // +0x018
    LUID                        ParentTokenId;              // +0x020
    
    //=========================================================================
    // +0x028 - Token Timing and Locking (24 bytes)
    //=========================================================================
    LARGE_INTEGER               ExpirationTime;             // +0x028
    PEX_PUSH_LOCK               TokenLock;                  // +0x030 (pointer)
    LUID                        ModifiedId;                 // +0x038
    
    //=========================================================================
    // +0x040 - PRIVILEGES (24 bytes) - PRIMARY EXPLOIT TARGET
    //=========================================================================
    SEP_TOKEN_PRIVILEGES        Privileges;                 // +0x040
    // Privileges.Present:          +0x040 (8 bytes)
    // Privileges.Enabled:          +0x048 (8 bytes)
    // Privileges.EnabledByDefault: +0x050 (8 bytes)
    
    //=========================================================================
    // +0x058 - Audit Policy (48 bytes)
    //=========================================================================
    SEP_AUDIT_POLICY            AuditPolicy;                // +0x058
    
    //=========================================================================
    // +0x088 - Session and Counts (32 bytes)
    //=========================================================================
    ULONG                       SessionId;                  // +0x088
    ULONG                       UserAndGroupCount;          // +0x08C
    ULONG                       RestrictedSidCount;         // +0x090
    ULONG                       VariableLength;             // +0x094
    ULONG                       DynamicCharged;             // +0x098
    ULONG                       DynamicAvailable;           // +0x09C
    ULONG                       DefaultOwnerIndex;          // +0x0A0
    ULONG                       Padding1;                   // +0x0A4
    
    //=========================================================================
    // +0x0A8 - SID and Group Pointers (48 bytes)
    //=========================================================================
    PSID_AND_ATTRIBUTES         UserAndGroups;              // +0x0A8
    PSID_AND_ATTRIBUTES         RestrictedSids;             // +0x0B0
    PSID                        PrimaryGroup;               // +0x0B8
    PULONG                      DynamicPart;                // +0x0C0
    PACL                        DefaultDacl;                // +0x0C8
    
    //=========================================================================
    // +0x0D0 - Token Type and Impersonation (8 bytes)
    //=========================================================================
    TOKEN_TYPE                  TokenType;                  // +0x0D0
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;        // +0x0D4
    
    //=========================================================================
    // +0x0D8 - Token Flags and State (16 bytes)
    //=========================================================================
    ULONG                       TokenFlags;                 // +0x0D8
    BOOLEAN                     TokenInUse;                 // +0x0DC
    BYTE                        Padding2[3];                // +0x0DD
    
    //=========================================================================
    // +0x0E0 - Integrity Level (16 bytes)
    //=========================================================================
    ULONG                       IntegrityLevelIndex;        // +0x0E0
    ULONG                       MandatoryPolicy;            // +0x0E4
    
    //=========================================================================
    // +0x0E8 - Logon Session Reference (8 bytes)
    //=========================================================================
    PSEP_LOGON_SESSION_REFERENCES LogonSession;             // +0x0E8
    
    //=========================================================================
    // +0x0F0 - Origin and Package (24 bytes)
    //=========================================================================
    LUID                        OriginatingLogonSession;    // +0x0F0
    SID_AND_ATTRIBUTES_HASH     SidHash;                    // +0x0F8 (280 bytes)
    SID_AND_ATTRIBUTES_HASH     RestrictedSidHash;          // +0x210 (280 bytes)
    
    //=========================================================================
    // +0x328 - Security Attributes (8 bytes)
    //=========================================================================
    PAUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION pSecurityAttributesInfo; // +0x328
    
    //=========================================================================
    // +0x330 - Package SID (8 bytes)
    //=========================================================================
    PVOID                       Package;                    // +0x330
    
    //=========================================================================
    // +0x338 - Capabilities (16 bytes)
    //=========================================================================
    PSID_AND_ATTRIBUTES         Capabilities;               // +0x338
    ULONG                       CapabilityCount;            // +0x340
    ULONG                       Padding3;                   // +0x344
    
    //=========================================================================
    // +0x348 - Capability Hash (280 bytes)
    //=========================================================================
    SID_AND_ATTRIBUTES_HASH     CapabilitiesHash;           // +0x348
    
    //=========================================================================
    // +0x460 - Lowbox and Trust (64 bytes)
    //=========================================================================
    PSEP_LOWBOX_NUMBER_ENTRY    LowboxNumberEntry;          // +0x460
    PSEP_CACHED_HANDLES_ENTRY   LowboxHandlesEntry;         // +0x468
    PAUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION pClaimAttributesInfo; // +0x470
    PVOID                       TrustLevelSid;              // +0x478
    
    //=========================================================================
    // +0x480 - Trust and Session (32 bytes)
    //=========================================================================
    PVOID                       TrustLinkedToken;           // +0x480
    PVOID                       IntegrityLevelSidValue;     // +0x488
    PVOID                       TokenSidValues;             // +0x490
    
    //=========================================================================
    // +0x498 - Locks and Singleton (16 bytes)
    //=========================================================================
    PSEP_LUID_TO_INDEX_MAP_ENTRY IndexEntry;                // +0x498
    PVOID                       DiagnosticInfo;             // +0x4A0
    
    //=========================================================================
    // +0x4A8 - Extended Variable Part
    //=========================================================================
    PVOID                       BnoIsolationHandlesEntry;   // +0x4A8
    PVOID                       SessionObject;              // +0x4B0
    ULONGLONG                   VariablePart;               // +0x4B8
    
} TOKEN, *PTOKEN;

// Forward declarations for types used in TOKEN
typedef struct _SEP_LOWBOX_NUMBER_ENTRY *PSEP_LOWBOX_NUMBER_ENTRY;
typedef struct _SEP_CACHED_HANDLES_ENTRY *PSEP_CACHED_HANDLES_ENTRY;
typedef struct _SEP_LUID_TO_INDEX_MAP_ENTRY *PSEP_LUID_TO_INDEX_MAP_ENTRY;

//=============================================================================
// TOKEN SIZE VERIFICATION
//=============================================================================

// Static assertion to verify TOKEN structure size
// Actual size may vary by Windows build
#define TOKEN_EXPECTED_SIZE_W11  0x4C0

//=============================================================================
// PRIVILEGE CONSTANTS - All Windows Privileges
//=============================================================================

// Privilege bit positions in SEP_TOKEN_PRIVILEGES
#define SE_CREATE_TOKEN_PRIVILEGE           2
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     3
#define SE_LOCK_MEMORY_PRIVILEGE            4
#define SE_INCREASE_QUOTA_PRIVILEGE         5
#define SE_MACHINE_ACCOUNT_PRIVILEGE        6
#define SE_TCB_PRIVILEGE                    7   // Act as part of OS
#define SE_SECURITY_PRIVILEGE               8
#define SE_TAKE_OWNERSHIP_PRIVILEGE         9
#define SE_LOAD_DRIVER_PRIVILEGE            10
#define SE_SYSTEM_PROFILE_PRIVILEGE         11
#define SE_SYSTEMTIME_PRIVILEGE             12
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    13
#define SE_INC_BASE_PRIORITY_PRIVILEGE      14
#define SE_CREATE_PAGEFILE_PRIVILEGE        15
#define SE_CREATE_PERMANENT_PRIVILEGE       16
#define SE_BACKUP_PRIVILEGE                 17
#define SE_RESTORE_PRIVILEGE                18
#define SE_SHUTDOWN_PRIVILEGE               19
#define SE_DEBUG_PRIVILEGE                  20
#define SE_AUDIT_PRIVILEGE                  21
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     22
#define SE_CHANGE_NOTIFY_PRIVILEGE          23
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        24
#define SE_UNDOCK_PRIVILEGE                 25
#define SE_SYNC_AGENT_PRIVILEGE             26
#define SE_ENABLE_DELEGATION_PRIVILEGE      27
#define SE_MANAGE_VOLUME_PRIVILEGE          28
#define SE_IMPERSONATE_PRIVILEGE            29
#define SE_CREATE_GLOBAL_PRIVILEGE          30
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE 31
#define SE_RELABEL_PRIVILEGE                32
#define SE_INC_WORKING_SET_PRIVILEGE        33
#define SE_TIME_ZONE_PRIVILEGE              34
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   35
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE 36

// All privileges mask
#define SE_ALL_PRIVILEGES_MASK              0xFFFFFFFFFFFFFFFF

// Critical privileges for exploitation
#define SE_DANGEROUS_PRIVILEGES \
    ((1ULL << SE_DEBUG_PRIVILEGE) | \
     (1ULL << SE_TCB_PRIVILEGE) | \
     (1ULL << SE_LOAD_DRIVER_PRIVILEGE) | \
     (1ULL << SE_TAKE_OWNERSHIP_PRIVILEGE) | \
     (1ULL << SE_BACKUP_PRIVILEGE) | \
     (1ULL << SE_RESTORE_PRIVILEGE) | \
     (1ULL << SE_IMPERSONATE_PRIVILEGE))

//=============================================================================
// KPROCESS - Kernel Process Block (Partial)
//=============================================================================

typedef struct _KPROCESS {
    DISPATCHER_HEADER           Header;                     // +0x000
    LIST_ENTRY                  ProfileListHead;            // +0x018
    ULONG_PTR                   DirectoryTableBase;         // +0x028
    LIST_ENTRY                  ThreadListHead;             // +0x030
    ULONG                       ProcessLock;                // +0x040
    ULONG                       ProcessTimerDelay;          // +0x044
    ULONGLONG                   DeepFreezeStartTime;        // +0x048
    // ... additional fields omitted for brevity
} KPROCESS, *PKPROCESS;

typedef struct _DISPATCHER_HEADER {
    union {
        struct {
            UCHAR   Type;
            UCHAR   Signalling;
            UCHAR   Size;
            UCHAR   Reserved1;
        };
        LONG    Lock;
    };
    LONG    SignalState;
    LIST_ENTRY  WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

//=============================================================================
// EPROCESS - Executive Process (Windows 10/11 22H2)
//=============================================================================

typedef struct _EPROCESS {
    //=========================================================================
    // +0x000 - KPROCESS (Kernel Process Block)
    //=========================================================================
    KPROCESS                    Pcb;                        // +0x000
    
    //=========================================================================
    // +0x438 - Process Lock and Timing
    //=========================================================================
    EX_PUSH_LOCK                ProcessLock;                // +0x438
    PVOID                       UniqueProcessId_Ptr;        // +0x440
    
    //=========================================================================
    // +0x448 - Active Process Links - Used for process enumeration
    //=========================================================================
    LIST_ENTRY                  ActiveProcessLinks;         // +0x448
    
    //=========================================================================
    // +0x458 - Process Rundown and Flags
    //=========================================================================
    EX_RUNDOWN_REF              RundownProtect;             // +0x458
    
    union {
        ULONG                   Flags2;                     // +0x460
        struct {
            ULONG   JobNotReallyActive          : 1;
            ULONG   AccountingFolded            : 1;
            ULONG   NewProcessReported          : 1;
            ULONG   ExitProcessReported         : 1;
            ULONG   ReportCommitChanges         : 1;
            ULONG   LastReportMemory            : 1;
            ULONG   ForceWakeCharge             : 1;
            ULONG   CrossSessionCreate          : 1;
            ULONG   NeedsHandleRundown          : 1;
            ULONG   RefTraceEnabled             : 1;
            ULONG   PicoCreated                 : 1;
            ULONG   EmptyJobEvaluated           : 1;
            ULONG   DefaultPagePriority         : 3;
            ULONG   PrimaryTokenFrozen          : 1;
            ULONG   ProcessVerifierTarget       : 1;
            ULONG   RestrictSetThreadContext    : 1;
            ULONG   AffinityPermanent           : 1;
            ULONG   AffinityUpdateEnable        : 1;
            ULONG   PropagateNode               : 1;
            ULONG   ExplicitAffinity            : 1;
            ULONG   ProcessExecutionState       : 2;
            ULONG   EnableReadVmLogging         : 1;
            ULONG   EnableWriteVmLogging        : 1;
            ULONG   FatalAccessTerminationRequested : 1;
            ULONG   DisableSystemAllowedCpuSet  : 1;
            ULONG   ProcessStateChangeRequest   : 2;
            ULONG   ProcessStateChangeInProgress : 1;
            ULONG   InPrivate                   : 1;
        };
    };
    
    union {
        ULONG                   Flags;                      // +0x464
        struct {
            ULONG   CreateReported              : 1;
            ULONG   NoDebugInherit              : 1;
            ULONG   ProcessExiting              : 1;
            ULONG   ProcessDelete               : 1;
            ULONG   ManageExecutableMemoryWrites : 1;
            ULONG   VmDeleted                   : 1;
            ULONG   OutswapEnabled              : 1;
            ULONG   Outswapped                  : 1;
            ULONG   FailFastOnCommitFail        : 1;
            ULONG   Wow64VaSpace4Gb             : 1;
            ULONG   AddressSpaceInitialized     : 2;
            ULONG   SetTimerResolution          : 1;
            ULONG   BreakOnTermination          : 1;
            ULONG   DeprioritizeViews           : 1;
            ULONG   WriteWatch                  : 1;
            ULONG   ProcessInSession            : 1;
            ULONG   OverrideAddressSpace        : 1;
            ULONG   HasAddressSpace             : 1;
            ULONG   LaunchPrefetched            : 1;
            ULONG   Background                  : 1;
            ULONG   VmTopDown                   : 1;
            ULONG   ImageNotifyDone             : 1;
            ULONG   PdeUpdateNeeded             : 1;
            ULONG   VdmAllowed                  : 1;
            ULONG   ProcessRundown              : 1;
            ULONG   ProcessInserted             : 1;
            ULONG   DefaultIoPriority           : 3;
            ULONG   ProcessSelfDelete           : 1;
            ULONG   SetTimerResolutionLink      : 1;
        };
    };
    
    //=========================================================================
    // +0x468 - Timing Information
    //=========================================================================
    LARGE_INTEGER               CreateTime;                 // +0x468
    ULONGLONG                   ProcessQuotaUsage[2];       // +0x470
    ULONGLONG                   ProcessQuotaPeak[2];        // +0x480
    ULONGLONG                   PeakVirtualSize;            // +0x490
    ULONGLONG                   VirtualSize;                // +0x498
    
    //=========================================================================
    // +0x4A0 - Session and Quota
    //=========================================================================
    LIST_ENTRY                  SessionProcessLinks;        // +0x4A0
    PVOID                       ExceptionPortData;          // +0x4B0
    
    //=========================================================================
    // +0x4B8 - TOKEN - PRIMARY EXPLOIT TARGET
    //=========================================================================
    EX_FAST_REF                 Token;                      // +0x4B8
    
    //=========================================================================
    // +0x4C0 - Working Set and Memory
    //=========================================================================
    ULONGLONG                   MmReserved;                 // +0x4C0
    EX_PUSH_LOCK                AddressCreationLock;        // +0x4C8
    EX_PUSH_REF                 PageTableCommitmentLock;    // +0x4D0
    
    //=========================================================================
    // +0x4D8 - Thread/Process Lists
    //=========================================================================
    PVOID                       RotateInProgress;           // +0x4D8
    PVOID                       ForkInProgress;             // +0x4E0
    
    //=========================================================================
    // +0x4E8 - Commit Charge
    //=========================================================================
    PVOID                       CommitChargeJob;            // +0x4E8
    
    //=========================================================================
    // +0x4F0 - Clone Root
    //=========================================================================
    PVOID                       CloneRoot;                  // +0x4F0
    
    //=========================================================================
    // +0x4F8 - Number Counters
    //=========================================================================
    ULONGLONG                   NumberOfPrivatePages;       // +0x4F8
    ULONGLONG                   NumberOfLockedPages;        // +0x500
    
    //=========================================================================
    // +0x508 - Win32 Process
    //=========================================================================
    PVOID                       Win32Process;               // +0x508
    
    //=========================================================================
    // +0x510 - Job Object
    //=========================================================================
    PVOID                       Job;                        // +0x510
    
    //=========================================================================
    // +0x518 - Section Object
    //=========================================================================
    PVOID                       SectionObject;              // +0x518
    
    //=========================================================================
    // +0x520 - Section Base Address
    //=========================================================================
    PVOID                       SectionBaseAddress;         // +0x520
    
    //=========================================================================
    // +0x528 - Cookie
    //=========================================================================
    ULONG                       Cookie;                     // +0x528
    ULONG                       Padding4;                   // +0x52C
    
    //=========================================================================
    // +0x530 - Work Queue
    //=========================================================================
    PVOID                       WorkingSetWatch;            // +0x530
    PVOID                       Win32WindowStation;         // +0x538
    PVOID                       InheritedFromUniqueProcessId; // +0x540
    
    //=========================================================================
    // +0x548 - Ownage
    //=========================================================================
    ULONGLONG                   OwnerProcessId;             // +0x548
    
    //=========================================================================
    // +0x550 - Image File Name (15 bytes + null)
    //=========================================================================
    UCHAR                       ImageFileName[15];          // +0x550
    UCHAR                       PriorityClass;              // +0x55F
    
    //=========================================================================
    // +0x560 - Security Port
    //=========================================================================
    PVOID                       SecurityPort;               // +0x560
    
    //=========================================================================
    // +0x568 - Wow64 Process
    //=========================================================================
    PVOID                       Wow64Process;               // +0x568 (WoW64)
    
    //=========================================================================
    // Additional fields continue...
    // (Truncated for brevity - full structure is ~0x880 bytes on x64)
    //=========================================================================
    
} EPROCESS, *PEPROCESS;

// Required for EPROCESS
typedef struct _EX_RUNDOWN_REF {
    union {
        ULONG_PTR   Count;
        PVOID       Ptr;
    };
} EX_RUNDOWN_REF, *PEX_RUNDOWN_REF;

typedef struct _EX_PUSH_REF {
    union {
        ULONG_PTR   Value;
        struct {
            ULONG_PTR   Locked  : 1;
            ULONG_PTR   Waiting : 1;
            ULONG_PTR   Waking  : 1;
            ULONG_PTR   Spare   : 61;
        };
    };
} EX_PUSH_REF, *PEX_PUSH_REF;

//=============================================================================
// EPROCESS OFFSETS FOR DIFFERENT WINDOWS VERSIONS
//=============================================================================

// Windows 10 1909 (Build 18363)
#define EPROCESS_TOKEN_OFFSET_W10_1909          0x360
#define EPROCESS_UNIQUEPROCESSID_OFFSET_W10_1909 0x2E8
#define EPROCESS_ACTIVEPROCESSLINKS_OFFSET_W10_1909 0x2F0
#define EPROCESS_IMAGEFILENAME_OFFSET_W10_1909  0x450

// Windows 10 2004+ / Windows 11 (Build 19041+)
#define EPROCESS_TOKEN_OFFSET_W10_2004          0x4B8
#define EPROCESS_UNIQUEPROCESSID_OFFSET_W10_2004 0x440
#define EPROCESS_ACTIVEPROCESSLINKS_OFFSET_W10_2004 0x448
#define EPROCESS_IMAGEFILENAME_OFFSET_W10_2004  0x5A8

// Default to modern offsets
#define EPROCESS_TOKEN_OFFSET                   EPROCESS_TOKEN_OFFSET_W10_2004
#define EPROCESS_UNIQUEPROCESSID_OFFSET         EPROCESS_UNIQUEPROCESSID_OFFSET_W10_2004
#define EPROCESS_ACTIVEPROCESSLINKS_OFFSET      EPROCESS_ACTIVEPROCESSLINKS_OFFSET_W10_2004
#define EPROCESS_IMAGEFILENAME_OFFSET           EPROCESS_IMAGEFILENAME_OFFSET_W10_2004

//=============================================================================
// TOKEN OFFSETS
//=============================================================================

#define TOKEN_PRIVILEGES_OFFSET                 0x40
#define TOKEN_PRIVILEGES_PRESENT_OFFSET         0x40
#define TOKEN_PRIVILEGES_ENABLED_OFFSET         0x48
#define TOKEN_PRIVILEGES_ENABLEDBYDEFAULT_OFFSET 0x50
#define TOKEN_SESSIONID_OFFSET                  0x88
#define TOKEN_TOKENTYPE_OFFSET                  0xD0
#define TOKEN_IMPERSONATIONLEVEL_OFFSET         0xD4
#define TOKEN_TOKENFLAGS_OFFSET                 0xD8
#define TOKEN_INTEGRITYLEVELINDEX_OFFSET        0xE0

//=============================================================================
// KTHREAD - Kernel Thread (Partial for ETHREAD access)
//=============================================================================

typedef struct _KTHREAD {
    DISPATCHER_HEADER           Header;                     // +0x000
    PVOID                       SListFaultAddress;          // +0x018
    ULONGLONG                   QuantumTarget;              // +0x020
    PVOID                       InitialStack;               // +0x028
    PVOID                       StackLimit;                 // +0x030
    PVOID                       StackBase;                  // +0x038
    EX_PUSH_LOCK                ThreadLock;                 // +0x040
    // ... more fields
    BYTE                        Reserved[0x70];             // Padding
    PVOID                       Process;                    // +0xB8 - Pointer to EPROCESS
} KTHREAD, *PKTHREAD;

//=============================================================================
// ETHREAD - Executive Thread (Partial)
//=============================================================================

typedef struct _ETHREAD {
    KTHREAD                     Tcb;                        // +0x000
    LARGE_INTEGER               CreateTime;                 // +0x???
    // ... more fields
} ETHREAD, *PETHREAD;

//=============================================================================
// KPCR - Kernel Processor Control Region
//=============================================================================

typedef struct _KPRCB;  // Forward declaration

typedef struct _KPCR {
    union {
        NT_TIB          NtTib;                              // +0x000
        struct {
            PVOID       GdtBase;                            // +0x000
            PVOID       TssBase;                            // +0x008
            ULONGLONG   UserRsp;                            // +0x010
            PVOID       Self;                               // +0x018
            struct _KPCR* CurrentPrcb;                      // +0x020
            PVOID       LockArray;                          // +0x028
            PVOID       Used_Self;                          // +0x030
        };
    };
    PVOID               IdtBase;                            // +0x038
    ULONGLONG           Unused[2];                          // +0x040
    UCHAR               Irql;                               // +0x050
    UCHAR               SecondLevelCacheAssociativity;      // +0x051
    UCHAR               ObsoleteNumber;                     // +0x052
    UCHAR               Fill0;                              // +0x053
    ULONG               Unused0[3];                         // +0x054
    USHORT              MajorVersion;                       // +0x060
    USHORT              MinorVersion;                       // +0x062
    ULONG               StallScaleFactor;                   // +0x064
    PVOID               Unused1[3];                         // +0x068
    ULONG               KernelReserved[15];                 // +0x080
    ULONG               SecondLevelCacheSize;               // +0x0BC
    ULONG               HalReserved[16];                    // +0x0C0
    ULONG               Unused2;                            // +0x100
    PVOID               KdVersionBlock;                     // +0x108
    PVOID               Unused3;                            // +0x110
    ULONG               PcrAlign1[24];                      // +0x118
    // +0x180 - KPRCB (Processor Control Block)
    struct _KPRCB*      Prcb;                               // +0x180
} KPCR, *PKPCR;

// KPRCB partial for CurrentThread access
typedef struct _KPRCB {
    ULONG               MxCsr;                              // +0x000
    UCHAR               LegacyNumber;                       // +0x004
    UCHAR               ReservedMustBeZero;                 // +0x005
    UCHAR               InterruptRequest;                   // +0x006
    UCHAR               IdleHalt;                           // +0x007
    PKTHREAD            CurrentThread;                      // +0x008 - Current running thread
    PKTHREAD            NextThread;                         // +0x010
    PKTHREAD            IdleThread;                         // +0x018
    // ... more fields
} KPRCB, *PKPRCB;

// GS segment offset to get current thread
// In kernel mode: gs:[0x188] = KPCR.Prcb.CurrentThread
#define KPCR_PRCB_CURRENTTHREAD_OFFSET          0x188

//=============================================================================
// NT_TIB - NT Thread Information Block
//=============================================================================

typedef struct _NT_TIB {
    PVOID               ExceptionList;
    PVOID               StackBase;
    PVOID               StackLimit;
    PVOID               SubSystemTib;
    union {
        PVOID           FiberData;
        ULONG           Version;
    };
    PVOID               ArbitraryUserPointer;
    struct _NT_TIB*     Self;
} NT_TIB, *PNT_TIB;

//=============================================================================
// SYSTEM PROCESS PID
//=============================================================================

#define SYSTEM_PROCESS_PID      4   // SYSTEM process always has PID 4

#endif // NTDEFS_H

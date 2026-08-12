/*
 * Wow64 filesystem and registry redirection
 *
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         wow64.dll
 * FILE:            dll/wow64/redirection.h
 * PROGRAMMER:      Marcin Jabłoński
 */

#pragma once

/* FIXME: for now, the WOW64 directory path is hardcoded. */
#define TMP_WOW_DIR L"C:\\ReactOS\\SysWOW64"

typedef struct _WOW64_PATH_REDIRECTION
{
    UNICODE_STRING From;
    UNICODE_STRING To;
} WOW64_PATH_REDIRECTION, *PWOW64_PATH_REDIRECTION;

static 
BOOLEAN 
RedirectPath(const WOW64_PATH_REDIRECTION* Redirection, 
             POBJECT_ATTRIBUTES ObjectAttributes)
{
    PUNICODE_STRING ObjectName = ObjectAttributes->ObjectName;
    const UNICODE_STRING* FromUnexpanded = &Redirection->From;
    const UNICODE_STRING* ToUnexpanded = &Redirection->To;
    
    NTSTATUS Status;
    
    UNICODE_STRING From, To;
    WCHAR FromBuffer[MAX_PATH] = { 0 };
    WCHAR ToBuffer[MAX_PATH] = { 0 };
    
    PUNICODE_STRING Buffer = NULL;
    USHORT NewLength;

    RtlInitEmptyUnicodeString(&To, ToBuffer, sizeof(ToBuffer));
    Status = RtlExpandEnvironmentStrings_U(NULL,
                                           (PUNICODE_STRING)ToUnexpanded,
                                           &To,
                                           NULL);
    ASSERT(NT_SUCCESS(Status));
    
    RtlInitEmptyUnicodeString(&From, FromBuffer, sizeof(FromBuffer));
    Status = RtlExpandEnvironmentStrings_U(NULL,
                                           (PUNICODE_STRING)FromUnexpanded,
                                           &From,
                                           NULL);
    ASSERT(NT_SUCCESS(Status));
    
    NewLength = ObjectName->Length - From.Length + To.Length;

    Buffer = Wow64AllocateTemp(sizeof(*Buffer) + NewLength);
    ASSERT(Buffer != NULL);

    Buffer->Buffer = (PWCHAR)(((ULONG_PTR)Buffer) + sizeof(*Buffer));
    
    if (_wcsnicmp(ObjectName->Buffer, From.Buffer, From.Length / sizeof(WCHAR)) == 0)
    {
        Buffer->Length = NewLength;
        
        RtlCopyMemory(Buffer->Buffer, To.Buffer, To.Length);
        
        RtlCopyMemory(Buffer->Buffer + To.Length / sizeof(WCHAR), 
                      ObjectName->Buffer + From.Length / sizeof(WCHAR),
                      ObjectName->Length - From.Length);

        ObjectAttributes->ObjectName = Buffer;  
        return TRUE;
    }
    return FALSE;
}

static 
BOOLEAN 
GetFileRedirect(OBJECT_ATTRIBUTES* attr)
{
    size_t i;

    if (PtrToUlong(NtCurrentTeb()->TlsSlots[WOW64_TLS_FILESYSREDIR]) == 0)
    {
        return FALSE;
    }
    
    static const WOW64_PATH_REDIRECTION Redirections[] = 
    {
    /* TODO: system directory shouldn't be hardcoded here */
#define REDIRECTION(From, To) { RTL_CONSTANT_STRING(From), RTL_CONSTANT_STRING(To) }
#ifdef TMP_WOW_DIR
        REDIRECTION(L"\\??\\%SystemRoot%\\system32", L"\\??\\" TMP_WOW_DIR),
#else
        REDIRECTION(L"\\??\\%SystemRoot%\\system32", L"\\??\\%SystemRoot%\\SysWOW64"),
#endif
        REDIRECTION(L"\\KnownDlls", L"\\KnownDlls32")
#undef  REDIRECTION
    };
    
    PUNICODE_STRING ObjectName = attr->ObjectName;
    
    if (!attr || !ObjectName || !ObjectName->Buffer)
    {
        return FALSE;
    }
    
    for (i = 0; i < sizeof(Redirections) / sizeof(*Redirections); i++)
    {
        if (RedirectPath(&Redirections[i], attr))
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Registry redirection
 *
 * For a 32-bit process the default view of certain keys is redirected under
 * Wow6432Node. KEY_WOW64_64KEY forces the 64 bit view, KEY_WOW64_32KEY forces the 32 bit
 * view. Both flags set is invalid!
 *
 * Handled:
 * HKLM\Software -> HKLM\Software\Wow6432Node
 * HKLM\Software\Classes\{CLSID,Interface,...} -> HKLM\Software\Classes\Wow6432Node\...
 * HKCU\...\Software\Classes\{CLSID,Interface,...} -> ...\Classes\Wow6432Node\...
 * 
 *
 * TODO: Full exception list
 * Windows has more exceptions, but they aren't in ReactOS's hives.
 */
static
BOOLEAN
IsPrefixMatch(
    _In_ PUNICODE_STRING Path,
    _In_ PCUNICODE_STRING Prefix)
{
    if (Path->Length < Prefix->Length)
        return FALSE;

    if (_wcsnicmp(Path->Buffer, Prefix->Buffer, Prefix->Length / sizeof(WCHAR)) != 0)
        return FALSE;

    /* Exact match or next char is a path separator */
    if (Path->Length == Prefix->Length)
        return TRUE;

    return Path->Buffer[Prefix->Length / sizeof(WCHAR)] == L'\\';
}

static
PUNICODE_STRING
GetHandleObjectName(
    _In_ HANDLE Handle)
{
    POBJECT_NAME_INFORMATION NameInfo;
    PUNICODE_STRING Result;
    ULONG Size = 0;
    NTSTATUS Status;

    Status = NtQueryObject(Handle, ObjectNameInformation, NULL, 0, &Size);
    if (Status != STATUS_INFO_LENGTH_MISMATCH && Status != STATUS_BUFFER_TOO_SMALL)
        return NULL;

    if (Size == 0)
        return NULL;

    NameInfo = Wow64AllocateTemp(Size);
    if (!NameInfo)
        return NULL;

    Status = NtQueryObject(Handle, ObjectNameInformation, NameInfo, Size, &Size);
    if (!NT_SUCCESS(Status))
        return NULL;

    if (!NameInfo->Name.Buffer || NameInfo->Name.Length == 0)
        return NULL;

    Result = Wow64AllocateTemp(sizeof(*Result));
    if (!Result)
        return NULL;

    *Result = NameInfo->Name;
    return Result;
}

static
PUNICODE_STRING
BuildAbsoluteRegistryPath(
    _In_ PCUNICODE_STRING RootName,
    _In_ PCUNICODE_STRING RelativeName)
{
    PUNICODE_STRING Result;
    USHORT NewLength;
    USHORT SeparatorLength = 0;
    BOOLEAN NeedSeparator;

    NeedSeparator = (RelativeName->Length != 0) &&
                    !(RootName->Length != 0 &&
                      RootName->Buffer[RootName->Length / sizeof(WCHAR) - 1] == L'\\') &&
                    (RelativeName->Buffer[0] != L'\\');

    if (NeedSeparator)
        SeparatorLength = sizeof(WCHAR);

    NewLength = RootName->Length + SeparatorLength + RelativeName->Length;

    Result = Wow64AllocateTemp(sizeof(*Result) + NewLength);
    if (!Result)
        return NULL;

    Result->Buffer = (PWCHAR)((ULONG_PTR)Result + sizeof(*Result));
    Result->Length = NewLength;
    Result->MaximumLength = NewLength;

    RtlCopyMemory(Result->Buffer, RootName->Buffer, RootName->Length);

    if (SeparatorLength)
        Result->Buffer[RootName->Length / sizeof(WCHAR)] = L'\\';

    RtlCopyMemory((PUCHAR)Result->Buffer + RootName->Length + SeparatorLength,
                  RelativeName->Buffer,
                  RelativeName->Length);

    return Result;
}

static
USHORT
FindSubstringOffset(
    _In_ PUNICODE_STRING Haystack,
    _In_ PCUNICODE_STRING Needle)
{
    USHORT hayLen = Haystack->Length / sizeof(WCHAR);
    USHORT needleLen = Needle->Length / sizeof(WCHAR);
    USHORT i;

    if (needleLen == 0 || hayLen < needleLen)
        return (USHORT)-1;

    for (i = 0; i <= hayLen - needleLen; i++)
    {
        if (_wcsnicmp(Haystack->Buffer + i, Needle->Buffer, needleLen) == 0)
        {
            /* ensure we matched on a path component boundary */
            if (i > 0 && Haystack->Buffer[i - 1] != L'\\')
                continue;
            return i * sizeof(WCHAR);
        }
    }
    return (USHORT)-1;
}
static
BOOLEAN
GetRegistryRedirect(
    _Inout_ POBJECT_ATTRIBUTES attr,
    _Inout_ PACCESS_MASK DesiredAccess,
    _Out_ NTSTATUS *RedirectStatus)
{
    static const UNICODE_STRING SoftwarePrefix =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software");
    static const UNICODE_STRING WowNode =
        RTL_CONSTANT_STRING(L"\\Wow6432Node");
    static const UNICODE_STRING ClassesComponent =
        RTL_CONSTANT_STRING(L"\\Software\\Classes");
    static const UNICODE_STRING ClassesSuffix =          /* SID_Classes */
        RTL_CONSTANT_STRING(L"_Classes");

    /* Under Software\Classes these stay redirected (even though Classes is shared) */
    static const UNICODE_STRING RedirectedUnderClasses[] =
    {
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes\\CLSID"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes\\Interface"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes\\DirectShow"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes\\Media Type"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes\\MediaFoundation"),
    };

    /* Same children under any user's Classes (both \Software\Classes and _Classes forms) */
    static const UNICODE_STRING RedirectedUnderUserClasses[] =
    {
        RTL_CONSTANT_STRING(L"\\CLSID"),
        RTL_CONSTANT_STRING(L"\\Interface"),
        RTL_CONSTANT_STRING(L"\\DirectShow"),
        RTL_CONSTANT_STRING(L"\\Media Type"),
        RTL_CONSTANT_STRING(L"\\MediaFoundation"),
    };

    /* The following shared keys include the ones that exist in ReactOS, and the ones that don't. 
     * This is the Win7+ table, and it might change in the future.
     * See: https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys
     */
    static const UNICODE_STRING SharedPrefixes[] =
    {
        /* Classes itself + shared children (CLSID/Interface/... forced above) */
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes\\Appid"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes\\HCP"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Clients"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\COM3"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Cryptography\\Calais\\Current"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Cryptography\\Calais\\Readers"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Cryptography\\Services"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\CTF\\SystemShared"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\CTF\\TIP"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\DFS"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Driver Signing"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\EnterpriseCertificates"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\EventSystem"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\MSMQ"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Non-Driver Signing"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Notepad\\DefaultFonts"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Ole"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\RAS"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Rpc"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\SystemCertificates"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\TermServLicensing"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\TransactionServer"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Cursors\\Schemes"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\KindMap"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\PreviewHandlers"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Setup"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Telephony\\Locations"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Console"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontDpi"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontLink"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontMapper"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Gre_Initialize"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Language Pack"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Ports"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Print"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Policies"),
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\RegisteredApplications"),
    };

    PUNICODE_STRING ObjectName;
    PUNICODE_STRING RootName;
    PUNICODE_STRING NewName;
    USHORT NewLength;
    USHORT InsertOffset;
    ACCESS_MASK Access;
    BOOLEAN Want32BitView;
    BOOLEAN RelativeOpen;
    ULONG i;
    BOOLEAN ForceRedirect = FALSE;
    BOOLEAN IsUserClassesChild = FALSE;

    *RedirectStatus = STATUS_SUCCESS;

    if (!attr || !attr->ObjectName || (!attr->ObjectName->Buffer && attr->ObjectName->Length))
        return FALSE;

    Access = *DesiredAccess;

    /* Both flags set is INVALID! */
    if ((Access & KEY_WOW64_32KEY) && (Access & KEY_WOW64_64KEY))
    {
        *RedirectStatus = STATUS_INVALID_PARAMETER;
        return FALSE;
    }

    if (Access & KEY_WOW64_64KEY)
        Want32BitView = FALSE;
    else if (Access & KEY_WOW64_32KEY)
        Want32BitView = TRUE;
    else
        Want32BitView = TRUE; /* WOW64 process default */

    *DesiredAccess = Access & ~(KEY_WOW64_32KEY | KEY_WOW64_64KEY);

    if (!Want32BitView)
        return FALSE;

    RelativeOpen = (attr->RootDirectory != NULL);

    if (!RelativeOpen)
    {
        ObjectName = attr->ObjectName;
    }
    else
    {
        /* Resolve what RootDirectory actually points to, since ObjectName is
         * meaningless on its own here. If we can't find out, don't redirect. */
        RootName = GetHandleObjectName(attr->RootDirectory);
        if (!RootName)
            return FALSE;

        ObjectName = BuildAbsoluteRegistryPath(RootName, attr->ObjectName);
        if (!ObjectName)
            return FALSE;
    }

    if (IsPrefixMatch(ObjectName, &SoftwarePrefix))
    {
        /* Already under Wow6432Node */
        if (ObjectName->Length >= SoftwarePrefix.Length + WowNode.Length &&
            _wcsnicmp(ObjectName->Buffer + (SoftwarePrefix.Length / sizeof(WCHAR)),
                      WowNode.Buffer,
                      WowNode.Length / sizeof(WCHAR)) == 0)
        {
            return FALSE;
        }

        /* Classes children that remain redirected */
        for (i = 0; i < RTL_NUMBER_OF(RedirectedUnderClasses); i++)
        {
            if (IsPrefixMatch(ObjectName, &RedirectedUnderClasses[i]))
            {
                ForceRedirect = TRUE;
                /* "\Registry\Machine\Software\Classes" length */
                InsertOffset = SoftwarePrefix.Length +
                               sizeof(L"\\Classes") - sizeof(WCHAR);
                break;
            }
        }

        if (!ForceRedirect)
        {
            for (i = 0; i < RTL_NUMBER_OF(SharedPrefixes); i++)
            {
                if (IsPrefixMatch(ObjectName, &SharedPrefixes[i]))
                    return FALSE;
            }

            /* or if it's an ordinary Software subkey, insert after Software */
            InsertOffset = SoftwarePrefix.Length;
        }
    }
    else
    {
        USHORT classesOffset;
        USHORT afterClasses;

        /* ...\Software\Classes\... */
        classesOffset = FindSubstringOffset(ObjectName, &ClassesComponent);
        if (classesOffset != (USHORT)-1)
        {
            afterClasses = classesOffset + ClassesComponent.Length;
        }
        else
        {
            /* \Registry\User\<SID>_Classes\... */
            classesOffset = FindSubstringOffset(ObjectName, &ClassesSuffix);
            if (classesOffset == (USHORT)-1)
                return FALSE;
            afterClasses = classesOffset + ClassesSuffix.Length;
        }

        /* Already under Wow6432Node */
        if (ObjectName->Length >= afterClasses + WowNode.Length &&
            _wcsnicmp(ObjectName->Buffer + (afterClasses / sizeof(WCHAR)),
                      WowNode.Buffer,
                      WowNode.Length / sizeof(WCHAR)) == 0)
        {
            return FALSE;
        }

        /* Only the special children get redirected */
        for (i = 0; i < RTL_NUMBER_OF(RedirectedUnderUserClasses); i++)
        {
            USHORT childOff = FindSubstringOffset(ObjectName,
                                                  &RedirectedUnderUserClasses[i]);
            if (childOff != (USHORT)-1 && childOff >= afterClasses)
            {
                IsUserClassesChild = TRUE;
                break;
            }
        }

        if (!IsUserClassesChild)
            return FALSE;

        InsertOffset = afterClasses;
    }

    NewLength = ObjectName->Length + WowNode.Length;
    NewName = Wow64AllocateTemp(sizeof(*NewName) + NewLength);
    if (!NewName)
        return FALSE;

    NewName->Buffer = (PWCHAR)((ULONG_PTR)NewName + sizeof(*NewName));
    NewName->Length = NewLength;
    NewName->MaximumLength = NewLength;

    RtlCopyMemory(NewName->Buffer, ObjectName->Buffer, InsertOffset);
    RtlCopyMemory(NewName->Buffer + (InsertOffset / sizeof(WCHAR)),
                  WowNode.Buffer,
                  WowNode.Length);

    if (ObjectName->Length > InsertOffset)
    {
        RtlCopyMemory(NewName->Buffer +
                          ((InsertOffset + WowNode.Length) / sizeof(WCHAR)),
                      ObjectName->Buffer + (InsertOffset / sizeof(WCHAR)),
                      ObjectName->Length - InsertOffset);
    }

    attr->ObjectName = NewName;

    if (RelativeOpen)
        attr->RootDirectory = NULL;

    return TRUE;
}

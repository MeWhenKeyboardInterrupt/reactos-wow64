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
 * For now, only handle the most important case:
 * \Registry\Machine\Software -> \Registry\Machine\Software\Wow6432Node
 *
 * TODO: Shared keys and the full exception list
 */
static
BOOLEAN
GetRegistryRedirect(
    _Inout_ POBJECT_ATTRIBUTES attr,
    _Inout_ PACCESS_MASK DesiredAccess)
{
    static const UNICODE_STRING SoftwarePrefix =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software");
    static const UNICODE_STRING WowNode =
        RTL_CONSTANT_STRING(L"\\Wow6432Node");
    PUNICODE_STRING ObjectName;
    PUNICODE_STRING NewName;
    USHORT NewLength;
    ACCESS_MASK Access;
    BOOLEAN Want32BitView;

    if (!attr || !attr->ObjectName || !attr->ObjectName->Buffer)
        return FALSE;

    /* TODO: Relative opens */
    if (attr->RootDirectory != NULL)
        return FALSE;

    Access = *DesiredAccess;

    if ((Access & KEY_WOW64_32KEY) && (Access & KEY_WOW64_64KEY))
        return FALSE;

    if (Access & KEY_WOW64_64KEY)
        Want32BitView = FALSE;
    else if (Access & KEY_WOW64_32KEY)
        Want32BitView = TRUE;
    else
        Want32BitView = TRUE; /* WOW64 process default */

    *DesiredAccess = Access & ~(KEY_WOW64_32KEY | KEY_WOW64_64KEY);

    if (!Want32BitView)
        return FALSE;

    ObjectName = attr->ObjectName;

    if (ObjectName->Length < SoftwarePrefix.Length)
        return FALSE;

    if (_wcsnicmp(ObjectName->Buffer,
                  SoftwarePrefix.Buffer,
                  SoftwarePrefix.Length / sizeof(WCHAR)) != 0)
    {
        return FALSE;
    }

    /* Already under Wow6432Node */
    if (ObjectName->Length >= SoftwarePrefix.Length + WowNode.Length &&
        _wcsnicmp(ObjectName->Buffer + (SoftwarePrefix.Length / sizeof(WCHAR)),
                  WowNode.Buffer,
                  WowNode.Length / sizeof(WCHAR)) == 0)
    {
        return FALSE;
    }

    NewLength = ObjectName->Length + WowNode.Length;
    NewName = Wow64AllocateTemp(sizeof(*NewName) + NewLength);
    if (!NewName)
        return FALSE;

    NewName->Buffer = (PWCHAR)((ULONG_PTR)NewName + sizeof(*NewName));
    NewName->Length = NewLength;
    NewName->MaximumLength = NewLength;

    RtlCopyMemory(NewName->Buffer, ObjectName->Buffer, SoftwarePrefix.Length);
    RtlCopyMemory(NewName->Buffer + (SoftwarePrefix.Length / sizeof(WCHAR)),
                  WowNode.Buffer,
                  WowNode.Length);

    if (ObjectName->Length > SoftwarePrefix.Length)
    {
        RtlCopyMemory(NewName->Buffer +
                          ((SoftwarePrefix.Length + WowNode.Length) / sizeof(WCHAR)),
                      ObjectName->Buffer + (SoftwarePrefix.Length / sizeof(WCHAR)),
                      ObjectName->Length - SoftwarePrefix.Length);
    }

    attr->ObjectName = NewName;
    return TRUE;
}
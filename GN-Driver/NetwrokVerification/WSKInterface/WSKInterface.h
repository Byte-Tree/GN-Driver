#pragma once
extern "C"
{
//#include <WS2tcpip.h>
#include <ntddk.h>
#include <wsk.h>
}

#define MEMORY_TAG 'MeTa'


class WSKInterfaceError
{
private:
	const char* _error_str = nullptr;

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);

public:
	WSKInterfaceError(const char* error);
	~WSKInterfaceError();

public:
	virtual char const* what() const throw();

};


//extern "C"
//{
//    NTSTATUS
//        NTAPI
//        KspUtilAddrInfoToAddrInfoEx(
//            _In_ PADDRINFOA AddrInfo,
//            _Out_ PADDRINFOEXW* AddrInfoEx
//        )
//    {
//        NTSTATUS Status;
//
//        //
//        // Convert NULL input into NULL output.
//        //
//
//        if (AddrInfo == NULL)
//        {
//            *AddrInfoEx = NULL;
//            return STATUS_SUCCESS;
//        }
//
//        //
//        // Allocate memory for the output structure.
//        //
//
//        PADDRINFOEXW Result = (PADDRINFOEXW)ExAllocatePoolWithTag(PagedPool, sizeof(ADDRINFOEXW), MEMORY_TAG);
//
//        if (Result == NULL)
//        {
//            Status = STATUS_INSUFFICIENT_RESOURCES;
//            goto Error1;
//        }
//
//        //
//        // Copy numeric values.
//        //
//
//        RtlZeroMemory(Result, sizeof(ADDRINFOEXW));
//        Result->ai_flags = AddrInfo->ai_flags;
//        Result->ai_family = AddrInfo->ai_family;
//        Result->ai_socktype = AddrInfo->ai_socktype;
//        Result->ai_protocol = AddrInfo->ai_protocol;
//        Result->ai_addrlen = AddrInfo->ai_addrlen;
//
//        //
//        // Copy canonical name.
//        //
//
//        ANSI_STRING CanonicalNameAnsi;
//        UNICODE_STRING CanonicalNameUnicode;
//
//        if (AddrInfo->ai_canonname)
//        {
//            RtlInitAnsiString(&CanonicalNameAnsi, AddrInfo->ai_canonname);
//
//            Status = RtlAnsiStringToUnicodeString(&CanonicalNameUnicode, &CanonicalNameAnsi, TRUE);
//
//            if (!NT_SUCCESS(Status))
//            {
//                goto Error2;
//            }
//
//            Result->ai_canonname = CanonicalNameUnicode.Buffer;
//        }
//
//        //
//        // Copy address.
//        //
//
//        Result->ai_addr = AddrInfo->ai_addr;
//
//        //
//        // Copy the next structure (recursively).
//        //
//
//        PADDRINFOEXW NextAddrInfo;
//        Status = KspUtilAddrInfoToAddrInfoEx(AddrInfo->ai_next, &NextAddrInfo);
//
//        if (!NT_SUCCESS(Status))
//        {
//            goto Error3;
//        }
//
//        Result->ai_next = NextAddrInfo;
//
//        //
//        // All done!
//        //
//
//        *AddrInfoEx = Result;
//
//        return Status;
//
//    Error3:
//        RtlFreeAnsiString(&CanonicalNameAnsi);
//
//    Error2:
//        ExFreePoolWithTag(Result, MEMORY_TAG);
//
//    Error1:
//        return Status;
//    }
//
//    NTSTATUS
//        NTAPI
//        KspUtilAddrInfoExToAddrInfo(
//            _In_ PADDRINFOEXW AddrInfoEx,
//            _Out_ PADDRINFOA* AddrInfo
//        )
//    {
//        NTSTATUS Status;
//
//        //
//        // Convert NULL input into NULL output.
//        //
//
//        if (AddrInfoEx == NULL)
//        {
//            *AddrInfo = NULL;
//            return STATUS_SUCCESS;
//        }
//
//        //
//        // Allocate memory for the output structure.
//        //
//
//        PADDRINFOA Result = (PADDRINFOA)ExAllocatePoolWithTag(PagedPool, sizeof(ADDRINFOA), MEMORY_TAG);
//
//        if (Result == NULL)
//        {
//            Status = STATUS_INSUFFICIENT_RESOURCES;
//            goto Error1;
//        }
//
//        //
//        // Copy numeric values.
//        //
//
//        RtlZeroMemory(Result, sizeof(ADDRINFOA));
//        Result->ai_flags = AddrInfoEx->ai_flags;
//        Result->ai_family = AddrInfoEx->ai_family;
//        Result->ai_socktype = AddrInfoEx->ai_socktype;
//        Result->ai_protocol = AddrInfoEx->ai_protocol;
//        Result->ai_addrlen = AddrInfoEx->ai_addrlen;
//
//        //
//        // Copy canonical name.
//        //
//
//        UNICODE_STRING CanonicalNameUnicode;
//        ANSI_STRING CanonicalNameAnsi;
//
//        if (AddrInfoEx->ai_canonname)
//        {
//            RtlInitUnicodeString(&CanonicalNameUnicode, AddrInfoEx->ai_canonname);
//            Status = RtlUnicodeStringToAnsiString(&CanonicalNameAnsi, &CanonicalNameUnicode, TRUE);
//
//            if (!NT_SUCCESS(Status))
//            {
//                goto Error2;
//            }
//
//            Result->ai_canonname = CanonicalNameAnsi.Buffer;
//        }
//
//        //
//        // Copy address.
//        //
//
//        Result->ai_addr = AddrInfoEx->ai_addr;
//
//        //
//        // Copy the next structure (recursively).
//        //
//
//        PADDRINFOA NextAddrInfo;
//        Status = KspUtilAddrInfoExToAddrInfo(AddrInfoEx->ai_next, &NextAddrInfo);
//
//        if (!NT_SUCCESS(Status))
//        {
//            goto Error3;
//        }
//
//        Result->ai_next = NextAddrInfo;
//
//        //
//        // All done!
//        //
//
//        *AddrInfo = Result;
//
//        return Status;
//
//    Error3:
//        RtlFreeAnsiString(&CanonicalNameAnsi);
//
//    Error2:
//        ExFreePoolWithTag(Result, MEMORY_TAG);
//
//    Error1:
//        return Status;
//    }
//
//    VOID
//        NTAPI
//        KspUtilFreeAddrInfo(
//            _In_ PADDRINFOA AddrInfo
//        )
//    {
//        //
//        // Free all structures recursively.
//        //
//
//        if (AddrInfo->ai_next)
//        {
//            KspUtilFreeAddrInfo(AddrInfo->ai_next);
//        }
//
//        //
//        // Free the canonical name buffer.
//        //
//
//        if (AddrInfo->ai_canonname)
//        {
//            ANSI_STRING CanonicalName;
//            RtlInitAnsiString(&CanonicalName, AddrInfo->ai_canonname);
//            RtlFreeAnsiString(&CanonicalName);
//        }
//
//        //
//        // Finally, free the structure itself.
//        //
//
//        ExFreePoolWithTag(AddrInfo, MEMORY_TAG);
//    }
//
//    VOID
//        NTAPI
//        KspUtilFreeAddrInfoEx(
//            _In_ PADDRINFOEXW AddrInfo
//        )
//    {
//        //
//        // Free all structures recursively.
//        //
//
//        if (AddrInfo->ai_next)
//        {
//            KspUtilFreeAddrInfoEx(AddrInfo->ai_next);
//        }
//
//        //
//        // Free the canonical name buffer.
//        //
//
//        if (AddrInfo->ai_canonname)
//        {
//            UNICODE_STRING CanonicalName;
//            RtlInitUnicodeString(&CanonicalName, AddrInfo->ai_canonname);
//            RtlFreeUnicodeString(&CanonicalName);
//        }
//
//        //
//        // Finally, free the structure itself.
//        //
//
//        ExFreePoolWithTag(AddrInfo, MEMORY_TAG);
//    }
//
//    //int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res)
//    //{
//    //    NTSTATUS Status;
//    //
//    //    //
//    //    // Convert node name to the UNICODE_STRING (if present).
//    //    //
//    //
//    //    ANSI_STRING NodeNameAnsi;
//    //    UNICODE_STRING NodeNameUnicode;
//    //    PUNICODE_STRING NodeName = NULL;
//    //
//    //    if (node)
//    //    {
//    //        RtlInitAnsiString(&NodeNameAnsi, node);
//    //        Status = RtlAnsiStringToUnicodeString(&NodeNameUnicode, &NodeNameAnsi, TRUE);
//    //
//    //        if (!NT_SUCCESS(Status))
//    //        {
//    //            goto Error1;
//    //        }
//    //
//    //        NodeName = &NodeNameUnicode;
//    //    }
//    //
//    //    //
//    //    // Convert service name to the UNICODE_STRING (if present).
//    //    //
//    //
//    //    ANSI_STRING ServiceNameAnsi;
//    //    UNICODE_STRING ServiceNameUnicode;
//    //    PUNICODE_STRING ServiceName = NULL;
//    //
//    //    if (service)
//    //    {
//    //        RtlInitAnsiString(&ServiceNameAnsi, service);
//    //        Status = RtlAnsiStringToUnicodeString(&ServiceNameUnicode, &ServiceNameAnsi, TRUE);
//    //
//    //        if (!NT_SUCCESS(Status))
//    //        {
//    //            goto Error2;
//    //        }
//    //
//    //        ServiceName = &ServiceNameUnicode;
//    //    }
//    //
//    //    //
//    //    // Convert "struct addrinfo" to the "ADDRINFOEXW".
//    //    //
//    //
//    //    PADDRINFOEXW Hints;
//    //    Status = KspUtilAddrInfoToAddrInfoEx((PADDRINFOA)hints, &Hints);
//    //
//    //    if (!NT_SUCCESS(Status))
//    //    {
//    //        goto Error3;
//    //    }
//    //
//    //    //
//    //    // All data is prepared, call the underlying API.
//    //    //
//    //
//    //    PADDRINFOEXW Result;
//    //    Status = KsGetAddrInfo(NodeName, ServiceName, Hints, &Result);
//    //
//    //    //
//    //    // Free the memory of the converted "Hints".
//    //    //
//    //
//    //    KspUtilFreeAddrInfoEx(Hints);
//    //
//    //    if (!NT_SUCCESS(Status))
//    //    {
//    //        goto Error3;
//    //    }
//    //
//    //    //
//    //    // Convert the result "ADDRINFOEXW" to the "struct addrinfo".
//    //    //
//    //
//    //    Status = KspUtilAddrInfoExToAddrInfo(Result, res);
//    //
//    //    //
//    //    // Free the original result.
//    //    //
//    //
//    //    KsFreeAddrInfo(Result);
//    //
//    //    if (!NT_SUCCESS(Status))
//    //    {
//    //        goto Error3;
//    //    }
//    //
//    //    return STATUS_SUCCESS;
//    //
//    //Error3:
//    //    RtlFreeUnicodeString(&ServiceNameUnicode);
//    //
//    //Error2:
//    //    RtlFreeUnicodeString(&NodeNameUnicode);
//    //
//    //Error1:
//    //    return Status;
//    //}
//}


class WSKInterface
{
private:
	WSK_REGISTRATION _wsk_registration = { NULL };
	WSK_PROVIDER_NPI _wsk_provider = { NULL };
	WSK_CLIENT_DISPATCH _wsk_client_dispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };

public:
	void* operator new(size_t size, POOL_TYPE pool_type = NonPagedPool);
	void operator delete(void* pointer);

public:
	WSKInterface();
	~WSKInterface();

public:

};


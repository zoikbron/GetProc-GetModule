#include <intrin.h>
#include "headers.h"



HMODULE (WINAPI * pLoadLibraryA)(LPCSTR lpLibFileName);

HMODULE WINAPI hpGetModuleHandle(LPCWSTR sModuleName){
#ifdef _M_IX86
MY_PEB * ProcEnvBlock = (MY_PEB *) __readfsdword(0x30);
#else
MY_PEB * ProcEnvBlock = (MY_PEB *) __readgsqword(0x60);
#endif
    
    if(sModuleName == NULL){
        
        return (HMODULE) (ProcEnvBlock->ImageBaseAddress);
    }
    PEB_LDR_DATA * Ldr = (PEB_LDR_DATA *) ProcEnvBlock->Ldr;
    
    LIST_ENTRY * List = &Ldr->InMemoryOrderModuleList;

    LIST_ENTRY * pFirst = List->Flink;

    for(LIST_ENTRY * iterator = pFirst; iterator != List;iterator = iterator->Flink){
        
        MY_LDR_DATA_TABLE_ENTRY * pEntry = (MY_LDR_DATA_TABLE_ENTRY *) ((BYTE *) iterator - sizeof(LIST_ENTRY));

        if(lstrcmpiW(pEntry->BaseDllName.Buffer,sModuleName)==0) return (HMODULE)pEntry->DllBase;
            

    }
    return NULL;




}

FARPROC WINAPI hpGetProcAddress(HMODULE hMod,char * sProcName){
    char * pBaseAddress = (char *) hMod;
    IMAGE_DOS_HEADER * pDosHeader;
    IMAGE_NT_HEADERS * pNtHeaders;
    IMAGE_OPTIONAL_HEADER * pOptionalHeader;
    IMAGE_DATA_DIRECTORY * pDataDirectory;
    IMAGE_EXPORT_DIRECTORY * pExportDirectory;
    void *pProcAddress;

    pDosHeader = (IMAGE_DOS_HEADER *) pBaseAddress;
    pNtHeaders = (IMAGE_NT_HEADERS *) (pBaseAddress + pDosHeader->e_lfanew);
    pOptionalHeader = (IMAGE_OPTIONAL_HEADER *) &pNtHeaders->OptionalHeader;
    pDataDirectory = (IMAGE_DATA_DIRECTORY *) (&pOptionalHeader->DataDirectory[0]);
    pExportDirectory = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddress + pDataDirectory->VirtualAddress);


    DWORD * pExportAddressTable = (DWORD *) (pBaseAddress + pExportDirectory->AddressOfFunctions);
    DWORD * pName = (DWORD *)(pBaseAddress + pExportDirectory->AddressOfNames);
    WORD * pOrdinals = (WORD *) (pBaseAddress + pExportDirectory->AddressOfNameOrdinals);




    if(((DWORD_PTR)sProcName >> 16)==0){
        DWORD ordinal = (WORD) sProcName & 0xFFFF;
        DWORD base = pExportDirectory->Base;

        if(ordinal < base || ordinal >= (base + pExportDirectory->NumberOfFunctions)) return NULL;

        pProcAddress = (FARPROC) (pBaseAddress + (DWORD_PTR) pExportAddressTable[ordinal - base]);
    }
    else{
        
        for(DWORD i=0;i < pExportDirectory->NumberOfNames;i++){
            char * sTemp = (char *) (pBaseAddress + (DWORD_PTR)pName[i]);

            if(lstrcmpiA(sProcName,sTemp)==0){
                pProcAddress = (FARPROC) (pBaseAddress +(DWORD_PTR) pExportAddressTable[pOrdinals[i]]);
                break;

            }

        }


    }

    if((char *)pProcAddress >= (char *) pExportDirectory && (char *)pProcAddress < (char*) (pExportDirectory + pDataDirectory->Size)){

        char * strFwdDll = _strdup((char*)pProcAddress);
        if(strFwdDll ==NULL) return NULL;

        char * strFunction = strchr(strFwdDll,'.');
        *strFunction = 0;
        strFunction++;

        if(pLoadLibraryA ==NULL){

            pLoadLibraryA =(HMODULE (WINAPI *)(LPCSTR)) hpGetProcAddress(hpGetModuleHandle(L"kernel32.dll"),"LoadLibraryA");


        }


        HMODULE hFwd = LoadLibraryA(strFwdDll);
        free(strFwdDll);
        if(hFwd == NULL) return NULL;
        pProcAddress = hpGetProcAddress(hFwd,strFunction);

        


    }
    return (FARPROC)pProcAddress;


    

}
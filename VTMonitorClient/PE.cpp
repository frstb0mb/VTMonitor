#include "PE.h"
#include <DbgHelp.h>

class pemap
{
private:
    HANDLE file;
    HANDLE map;
    PIMAGE_DOS_HEADER dosheader;
    PIMAGE_NT_HEADERS ntheader;

    void clear()
    {
        ntheader = NULL;
        if (dosheader) {
            UnmapViewOfFile(dosheader);
            dosheader = NULL;
        }
        if (map) {
            CloseHandle(map);
            map = NULL;
        }
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
            file = INVALID_HANDLE_VALUE;
        }
    }

public:
    pemap()
    {
        file = INVALID_HANDLE_VALUE;
        map = NULL;
        dosheader = NULL;
        ntheader = NULL;
    }
    ~pemap()
    {
        clear();
    }
    bool mapping(const wchar_t* filename)
    {
        if (filename == NULL)
            return false;

        file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE)
            return false;

        map = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!map) {
            clear();
            return false;
        }
        dosheader = reinterpret_cast<PIMAGE_DOS_HEADER>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
        if (!dosheader) {
            clear();
            return false;
        }

        try
        {
            if (dosheader->e_magic != 'ZM') {
                clear();
                return false;
            }
            ntheader = ImageNtHeader(dosheader);
            if (ntheader->Signature != 'EP' || ntheader->FileHeader.Machine != 0x8664 ||
                !(ntheader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
                clear();
                return false;
            }
            return true;
        }
        catch (...)
        {
        }

        return false;
    }
    const PIMAGE_DOS_HEADER getdos() const
    {
        return dosheader;
    }
    const PIMAGE_NT_HEADERS getnt() const
    {
        return ntheader;
    }
};

std::unique_ptr<BYTE[]> LoadPE(LPCWSTR path, DWORD &entry, PRUNTIME_FUNCTION &functables)
{
    // pemap for loading PE
    pemap loadinfo;
    if (!loadinfo.mapping(path)) {
        wprintf(L"[ERROR] pemap is faild\n");
        return nullptr;
    }

    // load
    auto loadsize = loadinfo.getnt()->OptionalHeader.SizeOfImage;
    auto loadedexe = std::make_unique<BYTE[]>(loadsize);
    DWORD oldprotect = 0;
    if (!VirtualProtect(loadedexe.get(), loadsize, PAGE_EXECUTE_READWRITE, &oldprotect)) {
        wprintf(L"[ERROR] VirtualProtect is failed %x\n", GetLastError());
        return nullptr;
    }

    // load DOS header and PE header
    memcpy_s(loadedexe.get(), loadsize, loadinfo.getdos(), loadinfo.getnt()->OptionalHeader.SizeOfHeaders);

    // load section data
    auto secheader = reinterpret_cast<PIMAGE_SECTION_HEADER>(loadinfo.getnt() + 1);
    ULONG_PTR lastaddr = reinterpret_cast<ULONG_PTR>(loadedexe.get()) + loadsize;
    auto dest = reinterpret_cast<ULONG_PTR>(loadedexe.get());
    auto src = reinterpret_cast<ULONG_PTR>(loadinfo.getdos());
    for (int i = 0; i < loadinfo.getnt()->FileHeader.NumberOfSections; i++) {
        auto destaddr = reinterpret_cast<LPVOID>(dest + secheader[i].VirtualAddress);
        auto srcaddr = reinterpret_cast<LPVOID>(src + secheader[i].PointerToRawData);
        memcpy_s(destaddr, lastaddr - reinterpret_cast<ULONG_PTR>(destaddr), srcaddr, secheader[i].SizeOfRawData);
    }


    // relocation
    ULONG relocsize;
    auto relocdesc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(ImageDirectoryEntryToData(loadinfo.getdos(), FALSE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &relocsize));
    if (!relocdesc) {
        wprintf(L"[ERROR] ImageDirectoryEntryToData is failed %x\n", GetLastError());
        return nullptr;
    }

    ULONG_PTR delta = dest - loadinfo.getnt()->OptionalHeader.ImageBase; // offset of between real and ideal
    ULONG sumbytes = 0;
    while (relocdesc->VirtualAddress && relocdesc->SizeOfBlock) {
        DWORD count = (relocdesc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD list = reinterpret_cast<PWORD>(relocdesc + 1);
        for (DWORD i = 0; i < count; i++) {
            if (list[i]) {
                auto ptr = reinterpret_cast<PULONG_PTR>(dest + relocdesc->VirtualAddress + (list[i] & 0xFFF)); // remain is type info but meaningless
                *ptr += delta;
            }
        }
        sumbytes += relocdesc->SizeOfBlock;
        relocdesc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG_PTR>(relocdesc) + relocdesc->SizeOfBlock);
    }

    // make IAT
    ULONG importsize = 0;
    auto importdesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ImageDirectoryEntryToData(loadinfo.getdos(), FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &importsize));
    if (!importdesc) {
        wprintf(L"[ERROR] ImageDirectoryEntryToData is failed %x\n", GetLastError());
        return nullptr;
    }
    while (importdesc->Characteristics) {
        auto mod = LoadLibraryA(reinterpret_cast<LPCSTR>(dest) + importdesc->Name); // loading necessary module
        if (!mod) {
            wprintf(L"[ERROR] LoadLibraryA is failed %x\n", GetLastError());
            return nullptr;
        }

        auto origthunk = reinterpret_cast<PIMAGE_THUNK_DATA>(dest + importdesc->OriginalFirstThunk);
        auto firsthutnk = reinterpret_cast<PIMAGE_THUNK_DATA>(dest + importdesc->FirstThunk);

        while (origthunk->u1.AddressOfData) {
            LPCSTR procname = NULL;
            if (origthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Import by ordinal
                procname = reinterpret_cast<LPCSTR>(origthunk->u1.Ordinal & 0xFFFF);
            }
            else {
                // Import by name
                auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dest + origthunk->u1.AddressOfData);
                procname = reinterpret_cast<LPCSTR>(ibn->Name);
            }
            ULONG_PTR funcaddr = reinterpret_cast<ULONG_PTR>(GetProcAddress(mod, procname));
            if (!funcaddr) {
                wprintf(L"[ERROR] GetProcAddress is failed %x\n", GetLastError());
                return nullptr;
            }
            firsthutnk->u1.Function = funcaddr;

            firsthutnk++;
            origthunk++;
        }
        importdesc++;
    }

    // Load Exception Info
    functables = reinterpret_cast<PRUNTIME_FUNCTION>(ImageDirectoryEntryToData(loadinfo.getdos(), FALSE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &importsize));
    if (functables) {
        if (!RtlAddFunctionTable(functables, importsize / sizeof(RUNTIME_FUNCTION), dest)) {
            wprintf(L"[ERROR] RtlAddFunctionTable %x\n", GetLastError());
        }
    }
    else {
        wprintf(L"[INFO] Function table is not found\n");
    }

    wprintf(L"[INFO] Loadaddr %llx\n", dest + loadinfo.getnt()->OptionalHeader.AddressOfEntryPoint);
    entry = loadinfo.getnt()->OptionalHeader.AddressOfEntryPoint;
    return loadedexe;
}
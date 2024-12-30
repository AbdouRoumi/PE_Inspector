#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


BOOL PeInspector(LPCSTR lpFileName, PBYTE* pPe, SIZE_T* sPe) {

	//Getting the DOS_Header

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPe;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}
	//Getting the NT_Headers

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPe + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	//Getting the FILE_Header

	IMAGE_FILE_HEADER ImgFileHdr = pImgNtHdrs->FileHeader;


	printf("\n\t#####################[ FILE HEADER ]#####################\n\n");

	if (ImgFileHdr.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		printf("Image file detected Executable as: ");

		if (ImgFileHdr.Characteristics & IMAGE_FILE_DLL)
			printf("DLL\n");
		else if (ImgFileHdr.Characteristics & IMAGE_SUBSYSTEM_NATIVE)
			printf("SYS\n");
		else
			printf("EXE\n");
	}


	printf("The file architecture is : %s\n", ImgFileHdr.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
	printf("Number Of Sections : %d \n", ImgFileHdr.NumberOfSections);
	printf("Size Of The Optional Header : %d Byte \n", ImgFileHdr.SizeOfOptionalHeader);

	// OPTIONAL HEADER 
	printf("\n\t#####################[ OPTIONAL HEADER ]#####################\n\n");



	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return FALSE;
	}

	printf("Size Of Code Section : %d \n", ImgOptHdr.SizeOfCode);
	printf("Address Of Code Section : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPe + ImgOptHdr.BaseOfCode), ImgOptHdr.BaseOfCode);
	printf("Size Of Initialized Data : %d \n", ImgOptHdr.SizeOfInitializedData);
	printf("Size Of Unitialized Data : %d \n", ImgOptHdr.SizeOfUninitializedData);
	printf("Preferable Mapping Address : 0x%p \n", (PVOID)ImgOptHdr.ImageBase);
	printf("Required Version : %d.%d \n", ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
	printf("Address Of The Entry Point : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPe + ImgOptHdr.AddressOfEntryPoint), ImgOptHdr.AddressOfEntryPoint);
	printf("Size Of The Image : %d \n", ImgOptHdr.SizeOfImage);
	printf("File CheckSum : 0x%0.8X \n", ImgOptHdr.CheckSum);
	printf("Number of entries in the DataDirectory array : %d \n", ImgOptHdr.NumberOfRvaAndSizes); // this is the same as `IMAGE_NUMBEROF_DIRECTORY_ENTRIES` - `16`




	//DATA DIRECTORIES

	printf("\n\t#####################[ DIRECTORIES ]#####################\n\n");
	//Export Functions
	IMAGE_DATA_DIRECTORY ExpDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	printf("[*] Export Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPe + ExpDataDir.VirtualAddress), ExpDataDir.Size, ExpDataDir.VirtualAddress);

	//Import Functions
	IMAGE_DATA_DIRECTORY ImpDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	printf("[*] Import Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPe + ImpDataDir.VirtualAddress), ImpDataDir.Size, ImpDataDir.VirtualAddress);

	//Resourcees

	IMAGE_DATA_DIRECTORY ResDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	printf("[*] Resource Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPe + ResDataDir.VirtualAddress), ResDataDir.Size, ResDataDir.VirtualAddress);

	//Exceptions

	IMAGE_DATA_DIRECTORY ExcDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	printf("[*] Exception Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPe + ExcDataDir.VirtualAddress), ExcDataDir.Size, ExcDataDir.VirtualAddress);

	//Base Relocation
	IMAGE_DATA_DIRECTORY BaseRelDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	printf("[*] Exception Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPe + BaseRelDataDir.VirtualAddress), BaseRelDataDir.Size, BaseRelDataDir.VirtualAddress);

	//TLS
	IMAGE_DATA_DIRECTORY TlsDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	printf("[*] TLS Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPe + TlsDataDir.VirtualAddress), TlsDataDir.Size, TlsDataDir.VirtualAddress);

	//IAT
	IMAGE_DATA_DIRECTORY IatDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	printf("[*] IAT Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPe + IatDataDir.VirtualAddress), IatDataDir.Size, IatDataDir.VirtualAddress);


	printf("\n\t#####################[ SECTIONS ]#####################\n\n");

	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgSectionHdr) + sizeof(IMAGE_NT_HEADERS));

	for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		printf("Name : %s \n", (CHAR*)pImgSectionHdr->Name);
		printf("\tSize : %d \n", pImgSectionHdr->SizeOfRawData);
		printf("\tRVA : 0x%0.8X \n", pImgSectionHdr->VirtualAddress);
		printf("\tAddress : 0x%p \n", (PVOID)(pPe + pImgSectionHdr->VirtualAddress));
		printf("\tRelocations : %d \n", pImgSectionHdr->NumberOfRelocations);
		printf("\tPermissions : ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READONLY | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READWRITE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("PAGE_EXECUTE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_EXECUTE_READWRITE");
		printf("\n\n");

		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}

	
	}





	BOOL ReadPeFile(LPCSTR lpFileName, PBYTE* pPe, SIZE_T* sPe) {
		HANDLE hFile = INVALID_HANDLE_VALUE;
		PBYTE pBuff = NULL;
		DWORD dwFileSize = 0, dwNumberOfBytesRead = 0;

		printf("Reading ....... %s\n", lpFileName);
		hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("CreateFileA Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		dwFileSize = GetFileSize(hFile, NULL);
		if (dwFileSize == 0) {
			printf("GetFileSize Failed With Error : %d \n", GetLastError());
			CloseHandle(hFile);
			return FALSE;
		}

		pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
		if (pBuff == NULL) {
			printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
			CloseHandle(hFile);
			return FALSE;
		}

		if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
			printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
			HeapFree(GetProcessHeap(), NULL, pBuff);
			CloseHandle(hFile);
			return FALSE;
		}

		CloseHandle(hFile);

		*pPe = pBuff;
		*sPe = dwFileSize;	

		printf("[+] DONE \n");
		return TRUE;
	}



	int main(int argc,char* argv[]) {

		if (argc < 2) {
			printf("Please Enter Pe File To Inspect ... \n");
			return -1;
		}
		


		PBYTE	pPE = NULL;
		SIZE_T	sPE = NULL;

		if (!ReadPeFile(argv[1], &pPE, &sPE)) {
			return -1;
		}

		printf("[+] \"%s\" Read At : 0x%p Of Size : %d \n", argv[1], pPE, sPE);

		PeInspector(pPE);


		printf("[#] Press <Enter> To Quit ... ");
		getchar();

		HeapFree(GetProcessHeap(), NULL, pPE);

		return 0;




	
	
	}


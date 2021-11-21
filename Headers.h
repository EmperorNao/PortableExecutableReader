#pragma once
#include <iostream>
#include <stdio.h>
#include <vector>
#include "./libdisasm/libdisasm/libdis.h"


#define WORD uint16_t
#define DWORD uint32_t
#define BYTE uint8_t
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8

#define BYTE1 0xFF
#define BYTE2 0xFF00

#define SECTION_ALIGMENT 0x50


#define ALIGN_DOWN(x, align)  (x & ~(align-1))
#define ALIGN_UP(x, align)    ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)


// Directory Entries
#define IMAGE_DIRECTORY_ENTRY_EXPORT          	0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          	        1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        	2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       	3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        	4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       	5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           	        6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       		7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    	7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       	8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             		9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    	10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  	11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            		12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   	13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 	14   // COM Runtime descriptor



#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM 0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define FUTURE 0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080
#define IMAGE_FILE_32BIT_MACHINE 0x0100
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
#define  IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
#define IMAGE_FILE_SYSTEM 0x1000
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000





typedef struct {
	WORD e_magic;      
	WORD e_cblp;       
	WORD e_cp;         
	WORD e_crlc;       
	WORD e_cparhdr;    
	WORD e_minalloc;   
	WORD e_maxalloc;   
	WORD e_ss;         
	WORD e_sp;         
	WORD e_csum;       
	WORD e_ip;         
	WORD e_cs;         
	WORD e_lfarlc;     
	WORD e_ovno;       
	WORD e_res[4];     
	WORD e_oemid;      
	WORD e_oeminfo;    
	WORD e_res2[10];   
	DWORD e_lfanew;     
} MY_IMAGE_DOS_HEADER;


typedef struct MY_IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} MY_IMAGE_FILE_HEADER;


typedef struct MY_IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} MY_IMAGE_DATA_DIRECTORY;


typedef struct MY_IMAGE_OPTIONAL_HEADER {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} MY_IMAGE_OPTIONAL_HEADER;


typedef struct MY_IMAGE_NT_HEADERS {
	DWORD                 Signature;
	IMAGE_FILE_HEADER     FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} MY_IMAGE_NT_HEADERS;


typedef struct MY_IMAGE_SECTION_HEADER {
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics;
} MY_IMAGE_SECTION_HEADER;


typedef struct {

	std::string name;
	DWORD size;

} section_info;


int def_section(DWORD rva, MY_IMAGE_SECTION_HEADER* sections, WORD n_sections, WORD section_aligment) {

	for (WORD i = 0; i < n_sections; ++i) 	{

		DWORD start = sections[i].VirtualAddress;
		DWORD end = start + ALIGN_UP(sections[i].Misc.VirtualSize, section_aligment);

		if (rva >= start && rva < end) {
			return i;
		}

	}
	return -1;

}


DWORD rva_to_offset(DWORD rva, MY_IMAGE_SECTION_HEADER* sections, WORD n_sections, WORD section_aligment) {

	int indexSection = def_section(rva, sections, n_sections, section_aligment);
	if (indexSection != -1) {
		return rva - sections[indexSection].VirtualAddress + sections[indexSection].PointerToRawData;
	}
	else {
		return 0;
	}

}


void set_section_flags(char* ch, DWORD flags) {

	if (flags & IMAGE_FILE_RELOCS_STRIPPED) {

		ch[15] = 'I';

	}
	if (flags & IMAGE_FILE_EXECUTABLE_IMAGE) {

		ch[14] = 'E';

	}
	// deprecated if (flags & IMAGE_FILE_LINE_NUMS_STRIPPED)
	// deprecated if (flags & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
	// deprecated if (flags & IMAGE_FILE_AGGRESSIVE_WS_TRIM)
	if (flags & IMAGE_FILE_LARGE_ADDRESS_AWARE) {

		ch[10] = 'L';

	}
	// to use in future #define FUTURE 0x0040
	// deprecated if (flags & IMAGE_FILE_BYTES_REVERSED_LO)
	if (flags & IMAGE_FILE_32BIT_MACHINE) {

		ch[7] = 'S';

	}
	if (flags & IMAGE_FILE_DEBUG_STRIPPED) {

		ch[6] = 'D';

	}
	if (flags & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {

		ch[5] = 'R';

	}
	if (flags & IMAGE_FILE_NET_RUN_FROM_SWAP) {

		ch[4] = 'N';

	}
	if (flags & IMAGE_FILE_SYSTEM) {

		ch[3] = 's';

	}
	if (flags & IMAGE_FILE_DLL) {

		ch[2] = 'D';

	}
	if (flags & IMAGE_FILE_UP_SYSTEM_ONLY) {

		ch[1] = 'U';

	}

}


std::vector<section_info> parse_args(int argc, char* argv[]) {

	if (argc < 3) {

		return {};

	}
	else {

		int i = 2; 
		while (i < argc) {



		}


	}


}


void print_section(FILE* fr, MY_IMAGE_SECTION_HEADER* sections, WORD section_index, WORD n_sections, DWORD Alignment,  DWORD size) {

	DWORD addr = rva_to_offset(sections[section_index].VirtualAddress, sections, n_sections, Alignment);
	unsigned long pos = ftell(fr);
	fseek(fr, addr, SEEK_SET);
	char* text = (char*)malloc(sections[section_index].SizeOfRawData);
	fread(text, 1, sections[section_index].SizeOfRawData, fr);

	DWORD min = size > sections[section_index].SizeOfRawData ? sections[section_index].SizeOfRawData : size;
	DWORD full_size = min;

	BYTE number_in_row = 15;
	for (DWORD j = 0; j + number_in_row < min; j += number_in_row) {

		int dig = (full_size - number_in_row > 0) ? number_in_row : full_size;
		for (int i = 0; i < dig; ++i) {

			printf("%02X ", BYTE(text[j + i]));

		}
		printf("\n");
		full_size -= number_in_row;

	}
	fseek(fr, pos, SEEK_SET);

}



int parse_executable(std::string filename, std::vector<section_info> sections_info) {

	FILE* fr;
	printf("START with file %s\n", filename.c_str());
	fopen_s(&fr, filename.c_str(), "r");
	printf("OPEN FILE\n");
	MY_IMAGE_DOS_HEADER header;
	fread(&header, sizeof(header), 1, fr);

	printf("magic = %i offset = %i\n", header.e_magic, header.e_lfanew);
	if (((header.e_magic & BYTE1) != 'M') or (((header.e_magic & BYTE2) >> 8) != 'Z')) {

		printf("Something wrong with file\n");
		return -1;

	}
	printf("str = %c%c\n", header.e_magic & BYTE1, (header.e_magic & BYTE2) >> 8);
	fseek(fr, header.e_lfanew, SEEK_SET);

	MY_IMAGE_NT_HEADERS nt_header;
	fread(&nt_header, sizeof(nt_header), 1, fr);

	printf("str = %c%c\n", nt_header.Signature & BYTE1, (nt_header.Signature & BYTE2) >> 8);
	printf("Machine = %X\n", nt_header.FileHeader.Machine);//nt_header.FileHeader.Machine & BYTE1, (nt_header.FileHeader.Machine & BYTE2) >> 8);
	if ((nt_header.OptionalHeader.Magic) == 0x10b) {

		printf("Format = PE32\n");

	}
	else if ((nt_header.OptionalHeader.Magic) == 0x20b) {

		printf("Format = PE32+\n");

	}

	WORD n_sections = nt_header.FileHeader.NumberOfSections;
	MY_IMAGE_SECTION_HEADER* sections = (MY_IMAGE_SECTION_HEADER*)malloc(sizeof(MY_IMAGE_SECTION_HEADER) * n_sections);
	fread(sections, sizeof(MY_IMAGE_SECTION_HEADER), n_sections, fr);
	printf("Number of section is %i\n", n_sections);

	for (WORD i = 0; i < n_sections; ++i) {

		printf("Section name %-8s\n", (char*)sections[i].Name);
		printf("Size of section is %i\n", sections[i].SizeOfRawData);
		DWORD flags = sections[i].Characteristics;
		
		char ch[17] = "---------------";
		
		// deprecated if (flags & IMAGE_FILE_BYTES_REVERSED_HI) {
		printf("Flags: %s\n", ch);

		if ( (strcmp((char*)sections[i].Name, ".text") == 0)) {

			DWORD addr = rva_to_offset(sections[i].VirtualAddress, sections, n_sections, nt_header.OptionalHeader.SectionAlignment);
			//DWORD addr = nt_h\eader.OptionalHeader.BaseOfCode;
			printf("Address = %X\n");
			unsigned long pos = ftell(fr);
			fseek(fr, addr, SEEK_SET);
			char* text = (char*)malloc(sections[i].SizeOfRawData);
			fread(text, 1, sections[i].SizeOfRawData, fr);

			//x86_insn_t insn;
			//unsigned buf_len = sections[i].SizeOfRawData;
			//unsigned offset = 0;
			//uint64_t buf_rva = sections[i].VirtualAddress;
			//unsigned char* buf = (unsigned char*)text;

			////int new_end = x86_disasm(buf, buf_len, buf_rva, offset, &insn);
			////printf("offset = %i, MNEMONIC = %s\n", offset, insn.mnemonic);
			//char output[100];
			///*x86_format_insn(&insn,output, 100, x86_asm_format::native_syntax);
			//printf(output);
			//printf("\n");*/
			////x86_format_header(output, 100, x86_asm_format::intel_syntax);
			////printf(output);
			////	exit(1);
			////offset += new_end;
			//int row = 1;
			//int new_end = -1;
			//while (offset < sections[i].SizeOfRawData) {

			//	new_end = x86_disasm(buf, buf_len, buf_rva, offset, &insn);
			//	if (new_end == 0) {

			//		break;

			//	}
			//	//printf("offset = %i, MNEMONIC = %s\n", offset, insn.mnemonic);
			//	x86_format_insn(&insn, output, 100, x86_asm_format::intel_syntax);
			//	printf("%08X : ", nt_header.OptionalHeader.ImageBase + insn.addr);
			//	printf(output);
			//	printf("\n");
			//	offset += new_end;
			//	row += 1;

			//}
			//exit(0);
			
			DWORD size = 200;
			print_section(fr, sections, i, n_sections, nt_header.OptionalHeader.SectionAlignment, size);

		}

	}
	return 0;

}

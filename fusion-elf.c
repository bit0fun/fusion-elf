/*
 * elf.c
 * Author Dylan Wadler dylan@fusion-core.org
 *
 * File for parsing Fusion-Core ELF Files to
 * memory mapped space
 * */

#include "fusion-elf.h"

/* Creates memory map of ELF file
 * Takes only filename as parameter
 * Returns pointer to memory map
 * if error occurs, return NULL */
addr_8_t* open_elf_map( const char* filename ){
	/* Open ELF file */
	elf_file = open( filename, O_RDONLY, (mode_t)0600);	
	
	/* Check if file could be opened */
	if( elf_file == -1 ){
		elf_error = ELF_OPEN;	/* Set error, couldn't open file */
		return NULL;	
	}
	
	/* Get file size */
	struct stat file_info = {0};
	
	/* check if file could be read */
	if( fstat( elf_file, &file_info) == -1 ){
		elf_error = ELF_SIZE;	
		return NULL;
	} 

	/* Check if file is empty */
	if( file_info.st_size == 0){
		elf_error = ELF_EMPTY;	
		return NULL;
	}

	/* perform map and return pointer */
	return mmap(0, file_info.st_size, PROT_READ, MAP_SHARED, elf_file, 0);
}

/* Frees memory map */
void close_elf_map( addr_8_t* map, intmax_t filesize){
	/* unmap and check if unmapped */
	if( munmap(map, filesize) == -1){
		elf_error = ELF_FREE;
	}
	close(elf_file);
}

/* Allocates and initializes memory pointer variables
 * returns error values for memory space creation
 * creates memory allocation for the following variables:
 * 	-memory_space
 * 	-dmem
 * 	-imem
 * 	-cprmem
 * 	-rdomem
 *
 * Only memory space is allocated, the others are pointers to within the
 * memory space. This is to save memory, and more accurately simulate
 * a real memory space.
 * 	*/
int create_memspace( void ){

}

/** ELF Header Functions **/

/* Checking ELF Header magic number */
int elf_check_magnum(Elf32_Ehdr *hdr) {
	if(!hdr)
		return -1;
	if(hdr->e_ident[EI_MAG0] != ELFMAG0){
		printf("Error: ELF Header EI_MAG0 incorrect. Exiting.\n");
		exit(1);
	}
	if(hdr->e_ident[EI_MAG1] != ELFMAG1){
		printf("Error: ELF Header EI_MAG1 incorrect. Exiting.\n");
		exit(1);
	}
	if(hdr->e_ident[EI_MAG2] != ELFMAG2){
		printf("Error: ELF Header EI_MAG2 incorrect. Exiting.\n");
		exit(1);
	}
	if(hdr->e_ident[EI_MAG3] != ELFMAG3){
		printf("Error: ELF Header EI_MAG3 incorrect. Exiting.\n");
		exit(1);
	}

	/* If the program gets this far, everything is fine */
	return 0;
}

/* Checking if architecture is supported */
int elf_check_supported_arch(Elf32_Ehdr *hdr){
	elf_check_magnum(hdr); /* Don't need to error handle as the program will exit before here. */

	if(hdr->e_ident[EI_CLASS] != ELFCLASS32){
		printf("Unsupported Elf File Class. Only 32 bit architectures at this time. Exiting.\n");
		exit(2);
	}
	if(hdr->e_ident[EI_DATA] != ELFDATA2MSB){
		printf("Unsupported Little Endian byte ordering. Only Big Engian binary files accepted. Exiting.\n");
		exit(2);
	}
	if(hdr->e_machine != EM_FUSION){
		printf("Unsupported Target. I don't know why you're trying to use a Fusion-Core ISA specific tool with a different architecture, but ok. Exiting.\n");
		exit(2);
	}
	if(hdr->e_ident[EI_VERSION] != EV_CURRENT){
		printf("Unsupported Elf File Version. Exiting.\n");
		exit(2);
	}
	return 0;
}

/* ELF Section Header Functions */

/* Accessing section header */
static inline Elf32_Shdr *elf_sheader(Elf32_Ehdr *hdr){
	return (Elf32_Shdr *)((intmax_t)hdr + hdr->e_shoff);
}

/* Accessing section */
static inline Elf32_Shdr *elf_section(Elf32_Ehdr *hdr, int i){
	return &elf_sheader(hdr)[i]; /* 'i' refers to the index of the sections */
}

/* Accessing String table  */
static inline char *elf_str_table(Elf32_Ehdr *hdr){
	if(hdr->e_shstrnidx == SHN_UNDEF)
		return NULL;
	return (char *)hdr + elf_section(hdr, hdr->e_shstrnidx)->sh_offset;
}

/* Looking up string in string table  */
static inline char *elf_lookup_string(Elf32_Ehdr *hdr, int offset){
	char *strtab = elf_str_table(hdr);
	if(strtab == NULL)
		return NULL;
	return strtab + offset;
}


/* Functions for Symbol Table */


/* Accessing symbol value */
static intmax_t elf_get_symval(Elf32_Ehdr *hdr, int table, uint index) {
	if(table == SHN_UNDEF || index == SHN_UNDEF)
		return 0;
	Elf32_Shdr *symtab = elf_section(hdr, table);
	uint32_t symtab_entries = (symtab->sh_size) / (symtab->sh_entsize);
	if(index >= symtab_entries){
		printf("Symbol Table Index out of range (%d:%u)\n", table, index);
		exit(3);
	}
	/* getting symbol from offset */
	intmax_t symaddr = (intmax_t)hdr + symtab->sh_offset;
	Elf32_Sym *symbol = &((Elf32_Sym *)symaddr)[index];

	if(symbol->st_shndx == SHN_UNDEF){
		Elf32_Shdr *strtab = elf_section(hdr, symtab->sh_link);
		const char *name = (const char *)hdr + strtab->sh_offset + symbol->st_name;

//		extern void *elf_lookup_symbol(const char *name); /* need to implement, simple implementation always returns NULL */
//		void *target = elf_lookup_symbol(name);
		void *target = NULL; /* forced for now */

		if(target == NULL) {
			/* If the external symbol is not found */
			if(ELF32_ST_BIND(symbol->st_info) & STB_WEAK) {
				/* Weak symbols are initialized to 0 */
				return 0;
			} else {
				printf("Undefined External Symbol: %s\nExiting.", name);
				exit(4);
			}
		} else {
			return (intmax_t) target; /* Target Found, return value */
		}
	
	/* Checking if symbol is absolute */
	} else if(symbol->st_shndx == SHN_ABS) {
		return symbol->st_value;	
	} else {
		/* Internally defined symbol */
		Elf32_Shdr *target = elf_section(hdr, symbol->st_shndx);
		return (intmax_t)hdr + symbol->st_value + target->sh_offset;
	}

}

/* For BSS sections and SHT_NOBITS */
static int elf_load_stage1 (Elf32_Ehdr *hdr) {
	Elf32_Shdr *shdr = elf_sheader(hdr);

	unsigned int i;
	/* Iterate over section headers */
	for(i = 0; i < hdr->e_shnum; i++){
		Elf32_Shdr *section = &shdr[i];	
		
		/* If the section isn't present in the file */
		if(section->sh_type == SHT_NOBITS) {
			/* Skip if section is empty */
			if(!section->sh_size)
				continue;
			/* If the section should be in memory */
			if(section->sh_flags & SHF_ALLOC) {
				/* Allocate and zero memory */
				void *mem = malloc(section->sh_size);
				memset(mem, 0, section->sh_size);
				/* Assign memory offset to section offset */
				section->sh_offset = (intmax_t)mem - (intmax_t)hdr;
#ifdef DEBUG
				printf("Allocated amount of memory for section: %ld", section->sh_size);
#endif /* DEBUG */
			}
		}
	}
	return 0;
}

/* Relocating Sections Functions */
static int elf_perform_reloc(Elf32_Ehdr *hdr, Elf32_Rela *rela, Elf32_Shdr *reltab){
	Elf32_Shdr *target = elf_section(hdr, reltab->sh_info);
	intmax_t addr = (intmax_t)hdr + target->sh_offset;
	intmax_t *ref = (intmax_t *)(addr + rela->r_addend);

	/* Symbol value */
	int symval = 0;
	if( ELF32_R_SYM(rela->r_info) != SHN_UNDEF ){
		symval = elf_get_symval(hdr, reltab->sh_link, ELF32_R_SYM(rela->r_info));
		if(symval == -1)
			return -1;
	}

	/* Actual relocation */

	switch(ELF32_R_TYPE(rela->r_info)) {
		case R_FUSION_NONE:
			/* Do nothing */
//			break;
		case R_FUSION_32:
//			*ref = (symval + *ref); /* need to double check on byte ordering */
		case R_FUSION_LI:

		case R_FUSION_LUI:
	/* Not used yet
	 *  case R_FUSION_LI_PCREL:
	 * case R_FUSION_LUI_PCREL:
	 */
		case R_FUSION_SYS:

		case R_FUSION_I:

		case R_FUSION_RELATIVE:

		case R_FUSION_LOAD:

		case R_FUSION_STORE:

		case R_FUSION_BRANCH:

		case R_FUSION_JUMP:

		case R_FUSION_JUMP_O:
		/* fall through for now */
			break;
		default:
			printf("Unsupported Relocation: %d\n", ELF32_R_TYPE(rela->r_info));
			exit(6);	
	}
	return symval;
}

static int elf_load_stage2(Elf32_Ehdr* hdr){
	Elf32_Shdr *shdr = elf_sheader(hdr);

	unsigned int i, idx;
	for(i = 0; i < hdr->e_shnum; i++){
		Elf32_Shdr *section = &shdr[i];
	
		/* If relocation section */
		if( section->sh_type == SHT_RELA){
			for(idx = 0; idx < ( section->sh_size / section->sh_entsize); idx++){
				Elf32_Rela* reltab = &((Elf32_Rel *)((intmax_t)hdr + section->sh_offset))[idx];	
				int result = elf_perform_reloc(hdr, reltab, section);
				if(result == -1){
					printf("Unable to perform relocation on symbol\n");			
					exit(5);
				}
			}
		}
	}
	return 0;
}

/* Loading ELF File */
static inline void *elf_load_rel(Elf32_Ehdr *hdr){
	int result;
	result = elf_load_stage1(hdr);
	if(result == -1){
		printf("Unable to load ELF file.\n");
		exit(7);
	}
	result = elf_load_stage2(hdr);
	if(result == -1){
		printf("Unable to load ELF file.\n");
		exit(7);
	}

	/* Parse the program header here, if present*/
	return (void *)hdr->e_entry;
}


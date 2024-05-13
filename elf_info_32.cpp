#include "elf_info.h"

void generate_elf_info_32_pots(std::vector<elf_info_32> *elf_info_vector, elf_info_32_group *elf_info_groups)
{
	int size;
	int i = 0;
	int counter = 0;

	// Split into pots determined by number of threads.
	size = elf_info_vector->size();

	double float_potSize = (double)size / THREAD_COUNT;
	int potSize = ceil(float_potSize); // Round up so we don't create more pots than threads.

	for (auto it = elf_info_vector->begin(); it != elf_info_vector->end(); ++it)
	{

		if (counter < potSize)
		{
			elf_info_groups->elf_info_32_pots[i].push_back(*it);
			counter++;
			continue;
		}
		else if (counter % potSize == 0)
		{
			i++; // Start a new group
		}

		elf_info_groups->elf_info_32_pots[i].push_back(*it);
		counter++;
	}
}

void resolve_dt_needed_names_32(pid_t pid, dynamic_info32 *dyn_info)
{
	page_boundaries page_bounds;
	uint64_t sizeToRead = 0;
	char *pch;
	char tmp_module_name[256];
	std::string module_name;

	if (dyn_info->dt_strtab_present)
	{
		for (int i = 0; i < dyn_info->dt_needed_indexes_vector.size(); i++)
		{
			ElfW(Addr) strtab_readfrom = dyn_info->dt_strtab + dyn_info->dt_needed_indexes_vector[i].index_into_dt_strtab;
			sizeToRead = dyn_info->dt_strsz - dyn_info->dt_needed_indexes_vector[i].index_into_dt_strtab;

			// Check to see if .dynstr (dynamic string table) has been modified by looking for a DT_NEEDED entry that sits beyond size given DT_STRSZ.
			if (dyn_info->dt_needed_indexes_vector[i].index_into_dt_strtab >= dyn_info->dt_strsz)
			{
				// dynstr has been manually added to
				dyn_info->dt_strtab_manipulated = true;

				// Tag module that sits outside normal string table
				dyn_info->dt_needed_indexes_vector[i].name_in_dynstr = false;

				// On Linux: The maximum length for a file name is 255 bytes.
				// Only read upto a page aligned boundary to ensure we don't try and read non readable pages in memory.
				get_page_boundaries(strtab_readfrom, &page_bounds);
				sizeToRead = (page_bounds.bytes_to_next_page < 255) ? page_bounds.bytes_to_next_page : 255;
			}

			char *strtab_mem = (char *)calloc(sizeToRead, 1);

			if (process_read(pid, (void *)strtab_mem, (void *)strtab_readfrom, sizeToRead) == -1)
			{
				printf("Failed to read strtab into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
			}
			else
			{

				// Add check for ';' character as well as this signifies the end of the string table.
				// If we find ';' then replace it with an end of string '\0' character.
				strcpy(tmp_module_name, strtab_mem);

				pch = strstr(tmp_module_name, ";");
				if (pch != NULL)
					strncpy(pch, "\0", 1);

				module_name = tmp_module_name;

				dyn_info->dt_needed_indexes_vector[i].module_name = sanitize_string(module_name);
			}

			free(strtab_mem);
		}
	}
}

bool get_headers_and_segment_info_mem_32(pid_t pid, Elf32_Addr base_vaddr, elf_mem_hdrs_32 *elf_mem_hdrs)
{

	uint8_t *pmem;
	Elf32_Phdr *phdr;

	if (process_read(pid, (void *)&elf_mem_hdrs->ehdr_mem, (void *)(uint64_t)base_vaddr, sizeof(Elf32_Ehdr)) == -1)
	{
		printf("Failed to read Executable headers with process_read() in function get_headers_and_segment_info: %s from pid: %i\n", strerror(errno), pid);
		return false;
	}

	// Type determines if relative or absoulte virtual address is given to get_dynamic_info function.
	if ((elf_mem_hdrs->ehdr_mem.e_type != ET_EXEC) && (elf_mem_hdrs->ehdr_mem.e_type != ET_DYN))
	{
		printf("Unable to recognize executable header from pid: %i\n", pid);
		return false;
	}

	// Allocate space on stack to store program headers.
	// Attacks could modify this if they manually insert additional headers after compilation
	// This would mean that the program headers actually start in a different position.
	// Try get the dynamic segment from the auxv vector.

	// Compare data with auxv.
	/*
	We expect:
		ehdr.e_phentsize 			== auxv_prog_hdr_info.phdr_sz
		ehdr.e_phnum	 			==	auxv_prog_hdr_info.phdr_count
		base_vaddr + ehdr.e_phoff	 == auxv_prog_hdr_info.phdr_addr
	*/

	// Headers have been shifted so that program headers won't start immediately after

	pmem = (uint8_t *)alloca(sizeof(Elf32_Ehdr) + (elf_mem_hdrs->ehdr_mem.e_phentsize * elf_mem_hdrs->ehdr_mem.e_phnum));

	/* Read in just the ehdr & phdrs and get the exact size of segments
	if (process_read(pid, pmem, (void *)base_vaddr, (sizeof(Elf64_Ehdr) + ehdr.e_phentsize * ehdr.e_phnum)) == -1)
	{
		printf("Failed to read Program headers with process_read() in function get_headers_and_segment_info: %s\n from pid: %i", strerror(errno), pid);
		return false;
	}
	*/

	if ((base_vaddr + sizeof(Elf32_Ehdr)) != (base_vaddr + elf_mem_hdrs->ehdr_mem.e_phoff))
	{
		// phdrs should start immediately after the ehdrs. This means they don't!
		// Headers are in non-standard place, indicating manipulation (as with more sophisticated DT_NEEDED infections)
		// Make sure we print out DT_NEEDED entries from here.
		elf_mem_hdrs->phdr_irregular_location_mem = true;
	}

	// Read in just the ehdr & phdrs and get the exact size of segments
	if (process_read(pid, pmem, (void *)(uint64_t)(base_vaddr + elf_mem_hdrs->ehdr_mem.e_phoff), (elf_mem_hdrs->ehdr_mem.e_phentsize * elf_mem_hdrs->ehdr_mem.e_phnum)) == -1)
	{
		printf("Failed to read Program headers with process_read() in function get_headers_and_segment_info: %s\n from pid: %i", strerror(errno), pid);
		return false;
	}

	// First entry phdr[0] is entry for header table itself
	// phdr = (Elf64_Phdr *)(pmem + ehdr.e_phoff);
	phdr = (Elf32_Phdr *)pmem;

	for (int i = 0; i < elf_mem_hdrs->ehdr_mem.e_phnum; i++)
	{

		if ((phdr[i].p_flags == (PF_X | PF_W | PF_R)) || (phdr[i].p_flags == (PF_X | PF_W)))
		{
			// RWX segment found!
			elf_mem_hdrs->rwx_or_wx_header_present_mem = true;
			elf_mem_hdrs->rwx_and_wx_headers_mem.push_back(phdr[i]);
		}

		switch (phdr[i].p_type)
		{
		case PT_LOAD: // All PT_LOAD Should be 4096 bytes aligned i.e. phdr[i].p_align = 0x1000

			if (phdr[i].p_flags == (PF_X | PF_R))
			{
				// TEXT segment (RX).
				elf_mem_hdrs->text_pHdr_mem_present = true;
				elf_mem_hdrs->text_pHdr_mem = phdr[i];
			}

			if (phdr[i].p_flags == (PF_W | PF_R))
			{
				// DATA segment (RW)
				elf_mem_hdrs->data_pHdr_mem = phdr[i];
			}

			if (phdr[i].p_flags == (PF_R) && (phdr[i].p_offset != 0x0))
			{
				// Segment containing .ro section
				elf_mem_hdrs->rodata_pHdr_mem = phdr[i];
			}

			break;
		case PT_DYNAMIC:
			elf_mem_hdrs->dynamic_segment_present = true;
			elf_mem_hdrs->dyn_pHdr_mem = phdr[i];
			break;
		}
	}

	return true;
}

bool get_headers_and_segment_info_disk_32(pid_t pid, std::string file_name, elf_disk_hrds_32 *elf_disk_hdrs, bool *disk_backed)
{
	int fd;
	struct stat st;
	// Elf64_Ehdr * ehdr;
	Elf32_Phdr *phdr;
	// char fuzzyHash[FUZZY_MAX_RESULT];
	size_t mapSize;
	uint8_t *mem;

	// Is the process/module backed by a file on disk?
	if (!exists(file_name))
	{
		printf("Unable to find disk executable file: '%s'. Relevant pid: %i. In function 'get_headers_and_segment_info_disk'\n", file_name.c_str(), pid);
		*disk_backed = false;
		return false;
	}

	// Open File
	// Should follow through SymLinks rather than opening the symlink itself.
	if ((fd = open(file_name.c_str(), O_RDONLY)) < 0)
	{
		printf("Failed to open ELF executable: '%s'. Relevant pid: %i. In function 'get_headers_and_segment_info_disk'\n", strerror(errno), pid);
		return false;
	}

	// Get status of file
	if (stat(file_name.c_str(), &st) < 0)
	{
		printf("Failed to get status of ELF executable: '%s'. Relevant pid: %i. In function 'get_headers_and_segment_info_disk'\n", strerror(errno), pid);
		close(fd);
		return false;
	}

	// Is file a regular file?
	if (!(st.st_mode & S_IFMT) == S_IFREG)
	{
		close(fd);
		return false;
	}

	if (st.st_size > 0)
	{
		mapSize = st.st_size;
		mem = (uint8_t *)calloc(1, mapSize);
	}
	else
	{
		close(fd);
		return false;
	}

	if (read(fd, mem, mapSize) == -1)
	{
		printf("Disk Read Failed in get_headers_and_segment_info_disk: %s for pid: %i\n", strerror(errno), pid);
		close(fd);
		free(mem);
		return false;
	}

	// Inital ELF header starts at offset 0.
	elf_disk_hdrs->ehdr_disk = *(Elf32_Ehdr *)mem;

	// We don't need to keep pHdr for disk. So Just use it to enumerate segments we care about.
	phdr = (Elf32_Phdr *)&mem[elf_disk_hdrs->ehdr_disk.e_phoff];

	// Check to see if phdrs start directly after ehdrs
	if (sizeof(Elf32_Ehdr) != elf_disk_hdrs->ehdr_disk.e_phoff)
	{
		// phdrs should start immediately after the ehdrs. This means they don't!
		elf_disk_hdrs->phdr_irregular_location_disk = true;
	}

	// Check to see if this is a valid ELF executable
	if ((elf_disk_hdrs->ehdr_disk.e_ident[0] != 0x7f) && (elf_disk_hdrs->ehdr_disk.e_ident[1] != 0x45) && (elf_disk_hdrs->ehdr_disk.e_ident[2] != 0x4c) && (elf_disk_hdrs->ehdr_disk.e_ident[3] != 0x46))
	{
		printf("Mapped file: %s is not an ELF executable. Under pid: %i. In function 'get_headers_and_segment_info_disk'\n", file_name.c_str(), pid);
		close(fd);
		free(mem);
		return false;
	}

	/*
	if (elf->ehdr_disk.e_ident[4] == 0x1)
	{
		printf("32-bit binary ignored\n");
		free(mem);
		return false;
	} */

	// Record number of program headers.
	// prog_headers->number_of_headers = ehdr->e_phnum;

	for (int i = 0; i < elf_disk_hdrs->ehdr_disk.e_phnum; i++)
	{
		if ((phdr[i].p_flags == (PF_X | PF_W | PF_R)) || (phdr[i].p_flags == (PF_X | PF_W)))
		{
			// RWX/WX segment found.
			elf_disk_hdrs->rwx_or_wx_header_present_disk = true;
			elf_disk_hdrs->rwx_and_wx_headers_disk.push_back(phdr[i]);
		}

		switch (phdr[i].p_type)
		{
		case PT_LOAD: // ALL PT_LOAD segments p_align == 0x1000.

			if (phdr[i].p_flags == (PF_X | PF_R))
			{
				// TEXT segment (RX) found.
				elf_disk_hdrs->text_pHdr_disk_present = true;
				elf_disk_hdrs->text_pHdr_disk = phdr[i];
			}

			if (phdr[i].p_flags == (PF_W | PF_R))
			{
				// DATA segment (RW) found.
				elf_disk_hdrs->data_pHdr_disk = phdr[i];
			}
		}
	}

	free(mem);
	close(fd);
	return true;
}

bool get_auxv32(elf_info_32 *elf)
{
	FILE *fd;
	char path_buffer[1024];
	char auxv_buffer[1024];
	size_t result = 0;

	snprintf(path_buffer, sizeof(path_buffer), "/proc/%d/auxv", elf->pid);

	if ((fd = fopen(path_buffer, "r")) == NULL)
	{
		printf("Cannot open %s for reading: %s\n", path_buffer, strerror(errno));
		return false;
	}

	// copy the /proc/<pid>/auxv into auxv_buffer
	result = fread(auxv_buffer, 1, 1024, fd);
	if (result == 0)
	{
		printf("Read error in get_auxv64: %s\n", strerror(errno));
		fclose(fd);
		return false;
	}

	fclose(fd);

	// Process is 64-bit
	Elf32_auxv_t *auxv = NULL;

	for (auxv = (Elf32_auxv_t *)auxv_buffer; auxv->a_type != AT_NULL && (char *)auxv < auxv_buffer + result; ++auxv)
	{
		switch (auxv->a_type)
		{
		case AT_PHDR: // Starting address in memory of program headers.
			elf->auxv_phdr_data.phdr_addr = auxv->a_un.a_val;
			break;
		case AT_PHENT: // Size of program header entry
			elf->auxv_phdr_data.phdr_sz = auxv->a_un.a_val;
			break;
		case AT_PHNUM: // Number of program headers
			elf->auxv_phdr_data.phdr_count = auxv->a_un.a_val;
			break;
		}
	}

	return true;
}

bool get_dynamic_info_32(pid_t pid, Elf32_Addr base_vaddr, Elf32_Ehdr ehdr_mem, Elf32_Phdr dyn_pHdr_mem, dynamic_info32 *dyn_info_mem)
{
	uint8_t *dynSegmentMem;
	Elf32_Dyn *dyn;
	bool endOfDyn = false;

	dynSegmentMem = (uint8_t *)alloca(dyn_pHdr_mem.p_memsz);

	// Get Dynamic segment
	// Executables (ET_EXEC) always use the same base address hence the dynamic segment address will be absolute.
	// Shared object (ET_DYN) compiled executables use relative addressing. So the base address needs to be added.
	if (ehdr_mem.e_type == ET_EXEC)
	{
		if (process_read(pid, dynSegmentMem, (void *)(uint64_t)dyn_pHdr_mem.p_vaddr, dyn_pHdr_mem.p_memsz) == -1)
		{
			printf("Failed to read Dynamic segment into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
			return false;
		}
	}
	else if (ehdr_mem.e_type == ET_DYN)
	{
		if (process_read(pid, dynSegmentMem, (void *)(uint64_t)(base_vaddr + dyn_pHdr_mem.p_vaddr), dyn_pHdr_mem.p_memsz) == -1)
		{
			printf("Failed to read Dynamic segment into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
			return false;
		}
	}

	// dyn = (Elf64_Dyn *)dynSegmentMem;
	dyn = (Elf32_Dyn *)dynSegmentMem;

	// Number of dynamic entries
	int numberof_DynEntries = (dyn_pHdr_mem.p_memsz / sizeof(Elf32_Dyn));

	// Use d_tag to identry starting address (and sometimes size) of various sections.
	int i = 0;
	int previousEntryNumber = 0;
	bool firstEntry = true;
	while ((i < numberof_DynEntries) && (!endOfDyn))
	{
		dt_needed_entries dtIndexes;

		switch (dyn[i].d_tag)
		{
		case DT_NULL:
			dyn_info_mem->dt_null_present = true;
			endOfDyn = true;
			break;
		case DT_PLTGOT:
			dyn_info_mem->dt_pltgot_present = true;
			dyn_info_mem->dt_pltgot = dyn[i].d_un.d_ptr;
			break;
		case DT_JMPREL:
			dyn_info_mem->dt_jmprel_present = true;
			dyn_info_mem->dt_jmprel = dyn[i].d_un.d_ptr;
			break;
		case DT_PLTREL:
			dyn_info_mem->dt_pltrel_present = true;
			dyn_info_mem->dt_pltrel = dyn[i].d_un.d_val;
			break;
		case DT_PLTRELSZ:
			dyn_info_mem->dt_pltrelsz_present = true;
			dyn_info_mem->dt_pltrelsz = dyn[i].d_un.d_val;
			break;
		case DT_STRTAB:
			dyn_info_mem->dt_strtab_present = true;
			dyn_info_mem->dt_strtab = dyn[i].d_un.d_ptr;
			break;
		case DT_SYMTAB:
			dyn_info_mem->dt_symtab_present = true;
			dyn_info_mem->dt_symtab = dyn[i].d_un.d_ptr;
			break;
		case DT_SYMENT:
			dyn_info_mem->dt_syment_present = true;
			dyn_info_mem->dt_syment = dyn[i].d_un.d_val;
			break;
		case DT_STRSZ:
			dyn_info_mem->dt_strsz_present = true;
			dyn_info_mem->dt_strsz = dyn[i].d_un.d_val;
			break;
		case DT_NEEDED:
			dyn_info_mem->dt_needed_present = true;

			// push back indexToName (dyn[i].d_un.d_val) and order DT_NEEDED entry appears in Dynamic segment (i).
			dtIndexes.index_into_dt_strtab = dyn[i].d_un.d_val;
			dtIndexes.dt_needed_index = i;
			dyn_info_mem->dt_needed_indexes_vector.push_back(dtIndexes);

			// If this is the first entry
			if (firstEntry)
			{
				previousEntryNumber = i;
				firstEntry = false;
				break;
			}
			// The follwing dt_needed entry should appear directly after.
			// If not then the DT_NEEDED entries are not sequential and thus have been tampered with.
			if ((previousEntryNumber + 1) != i)
			{
				dyn_info_mem->dt_needed_wrong_order = true;
			}
			// update previous entry number
			previousEntryNumber = i;
			break;
		case DT_DEBUG:
			dyn_info_mem->dt_debug_present = true;
			dyn_info_mem->dt_debug = dyn[i].d_un.d_ptr;
			break;
		case DT_HASH:
			// The DT_HASH tag can appear as a placeholder but still be empty. i.e. 0.
			if (dyn[i].d_un.d_ptr != 0)
			{
				dyn_info_mem->dt_hash_present = true;
				dyn_info_mem->dt_hash = dyn[i].d_un.d_ptr;
			}
			break;
		case DT_GNU_HASH:
			dyn_info_mem->dt_gnu_hash_present = true;
			dyn_info_mem->dt_gnu_hash = dyn[i].d_un.d_ptr;
			break;
		case DT_PREINIT_ARRAY:
			dyn_info_mem->dt_preinit_array_present = true;
			dyn_info_mem->dt_preinit_array = dyn[i].d_un.d_ptr;
			break;
		case DT_PREINIT_ARRAYSZ:
			dyn_info_mem->dt_preinit_arraysz_present = true;
			dyn_info_mem->dt_preinit_arraysz = dyn[i].d_un.d_val;

			// 8 byte address for x64
			dyn_info_mem->preinit_array_func_count = dyn[i].d_un.d_val / 8;
			break;
		case DT_INIT:
			dyn_info_mem->dt_init_present = true;
			dyn_info_mem->dt_init = dyn[i].d_un.d_ptr;
			break;
		case DT_INIT_ARRAY:
			dyn_info_mem->dt_init_array_present = true;
			dyn_info_mem->dt_init_array = dyn[i].d_un.d_ptr;
			break;
		case DT_INIT_ARRAYSZ:
			dyn_info_mem->dt_init_arraysz_present = true;
			dyn_info_mem->dt_init_arraysz = dyn[i].d_un.d_val;

			// 8 byte address for x64
			dyn_info_mem->init_array_func_count = dyn[i].d_un.d_val / 8;
			break;
		case DT_FINI:
			dyn_info_mem->dt_fini_present = true;
			dyn_info_mem->dt_fini = dyn[i].d_un.d_ptr;
			break;
		case DT_FINI_ARRAY:
			dyn_info_mem->dt_fini_array_present = true;
			dyn_info_mem->dt_fini_array = dyn[i].d_un.d_ptr;
			break;
		case DT_FINI_ARRAYSZ:
			dyn_info_mem->dt_fini_arraysz_present = true;
			dyn_info_mem->dt_fini_arraysz = dyn[i].d_un.d_val;

			// 8 byte address for x64
			dyn_info_mem->fini_array_func_count = dyn[i].d_un.d_val / 8;
			break;
		}
		i++;
	}

	// Calculate number of GOT entries depending the arch. Usually this should be Rela (32-bit) / Rela (64-bit) but there maybe exceptions to this, hence why it has been left in.
	if (dyn_info_mem->dt_pltrel_present)
	{
		if (dyn_info_mem->dt_pltrel == DT_REL)
		{
			dyn_info_mem->got_entries = dyn_info_mem->dt_pltrelsz / sizeof(Elf32_Rel);
		}
		else if (dyn_info_mem->dt_pltrel == DT_RELA)
		{
			dyn_info_mem->got_entries = dyn_info_mem->dt_pltrelsz / sizeof(Elf32_Rela);
		}
		else
		{
			// Error.
		}

		// GOT will always have 3 reserved entries before function pointers hence got_entries should be incremented by 3 to account for these;
		dyn_info_mem->got_entries += 3;
	}

	return true;
}

bool get_got_32(pid_t pid, dynamic_info32 dyn_info, std::vector<got_value_32> *got_value_vector, Elf32_Addr *link_map_got)
{
	/* Function description :
	1. Function gets GLOBAL_OFFSET_TABLE (GOT) from memory using address from the dynamic segment.
	2. Function collects-
			(i)  The offset of each GOT entry.
			(ii) The virtual function addresses contained within that entry.
	3. The first 3 entries are not collected in gotValues, they are reserved for-
			GOT[0] - Address to dynamic segment pointer
			GOT[1] - Address of link_map structure pointer
			GOT[2] - Address of dynamic linkers _dl_runtime_resolve() function pointer
	*/

	uint8_t *got_mem;
	Elf32_Addr *GLOBAL_OFFSET_TABLE;
	got_value_32 got_entry;

	// If there is no pltgot, pltrel OR got_entries then quit.
	if ((dyn_info.got_entries == 0) || (!dyn_info.dt_pltgot_present) || (!dyn_info.dt_pltrel_present))
	{
		return false;
	}

	// Allocate buffer on stack to store size of GOT
	got_mem = (uint8_t *)alloca((dyn_info.got_entries * sizeof(Elf32_Addr)));

	// Get GOT - .plt.got is in the DATA segment
	if (process_read(pid, got_mem, (void *)(uint64_t)dyn_info.dt_pltgot, (dyn_info.got_entries * sizeof(Elf32_Addr))) == -1)
	{
		printf("Failed to read GOT table with process_read() in function got_got: %s\n", strerror(errno));
		return false;
	}

	GLOBAL_OFFSET_TABLE = (Elf32_Addr *)got_mem;

	// Skip the first three addresses (4 bytes each for 32-bit, 12 bytes total).
	int func_offset = sizeof(Elf32_Addr) * 3;

	// link_map location
	*link_map_got = GLOBAL_OFFSET_TABLE[1];

	// We are skipping the first three entries
	for (int j = 3; j < dyn_info.got_entries; j++)
	{
		got_entry.GOT_entry_number = j;
		got_entry.vaddr_of_entry = dyn_info.dt_pltgot + func_offset;
		got_entry.func_pointer = (Elf32_Addr)GLOBAL_OFFSET_TABLE[j];
		got_value_vector->push_back(got_entry);
		func_offset += sizeof(Elf32_Addr); // Increment to next address (8bytes for x64, 4 bytes for x86)
	}

	return true;
}

bool get_link_map_32(pid_t pid, dynamic_info32 *dyn_info)
{
	Elf32_Addr link_map_location;

	// We create our own r_debug version outside of that in <link.h> as the ElfW() Macros don't work when interrogating the address space of a 32-bit process on a 64-bit OS.
	r_debug_32 debugSection;

	if (dyn_info->dt_debug_present)
	{
		if (process_read(pid, &debugSection, (const void *)(uint64_t)dyn_info->dt_debug, sizeof(r_debug_32)))
		{
			printf("Failed to read r_debug with process_read() in function get_link_map_64: %s for pid: %i\n", strerror(errno), pid);
			return false;
		}
		else
		{
			link_map_location = debugSection.r_map;
		}
	}
	else if (dyn_info->link_map_got != 0x0)
	{
		// Contrary to the documentation this isn't always reliable, possibly add another check through Auxiliary vector?
		// https://reverseengineering.stackexchange.com/questions/6525/elf-link-map-when-linked-as-relro
		// We can get r_debug address from the auxiliary vector.
		// https://www.cs.kent.ac.uk/people/staff/srk21/blog/2015/07/16/
		// http://articles.manugarg.com/aboutelfauxiliaryvectors.html
		link_map_location = dyn_info->link_map_got;
	}
	else
	{
		printf("Failed to locate link_map_location in function get_link_map_64 for pid: %i\n", pid);
		return false;
	}

	// link_map_32 manually added - This is because link_map in <link.h> not sutable due to ElfW macros, which generate incorrect size structs for the 32-bit process address space, when running the tool on a 64-bit OS.
	custom_link_map_32 link_map_entry; // link_map_32 with libary name field added.

	std::vector<uint32_t> forward_pointer;

	// Read first link_map struct from mem.
	if (process_read(pid, &link_map_entry, (const void *)(uint64_t)link_map_location, sizeof(link_map_32)))
	{
		printf("Failed to read link_map with process_read() in function get_link_map_32: %s for pid: %i\n", strerror(errno), pid);
		return false;
	}
	else
	{
		link_map_entry.library_name = get_mod_name(pid, (Elf64_Addr)link_map_entry.l_name);

		// link_map->push_back(link_map_entry);
		dyn_info->link_map.push_back(link_map_entry);

		forward_pointer.push_back(link_map_location);

		// Check to see if the next item in the linked list is zero or an element we have already seen. // We may encounter issues with (link_map_entry.l_next != 0) if we encounter a nullptr that != 0.
		while ((!contains(forward_pointer, (uint32_t)link_map_entry.l_next)) && (link_map_entry.l_next != 0))
		{
			forward_pointer.push_back((uint32_t)link_map_entry.l_next);

			if (process_read(pid, &link_map_entry, (const void *)(uint64_t)link_map_entry.l_next, sizeof(link_map_32)))
			{
				printf("Failed to read link_map with process_read() in function get_link_map_32: %s for pid: %i\n", strerror(errno), pid);
				return false;
			}

			link_map_entry.library_name = get_mod_name(pid, (Elf64_Addr)link_map_entry.l_name);

			// link_map->push_back(link_map_entry);
			dyn_info->link_map.push_back(link_map_entry);
		}
	}

	return true;
}

void collect_results32(pid_t pid, std::vector<elf_info_32> *elf_info_32_vector)
{
	elf_info_32 elf;
	utsname systeminfo;
	uname(&systeminfo);

	elf.pid = pid;

	elf.base_vaddr = get_proc_base(elf.pid);

	if (elf.base_vaddr == -1)
	{
		// Invalid base address. Quit.
		return;
	}

	// Get process & system details.
	get_process_start_time(elf.pid, &elf.proc_start_time);
	elf.process_path = get_process_path(elf.pid);
	elf.cmdline = get_process_cmdline(elf.pid);
	elf.ppid = get_ppid(elf.pid);
	elf.hostname = systeminfo.nodename;

	// Future possible heuristic - Try and grab .ro section to look for static function argument variable to dlopen calls.
	if (!get_headers_and_segment_info_mem_32(elf.pid, elf.base_vaddr, &elf.elf_mem_hdrs))
	{
		printf("Failed to read process headers for pid: %d in collect_results64\n", elf.pid);
		return;
	}

	if (!get_headers_and_segment_info_disk_32(elf.pid, elf.process_path, &elf.elf_disk_hdrs, &elf.disk_backed))
	{
		printf("Failed to read disk headers for pid: %d in collect_results64\n", elf.pid);
		// Maybe we should continue if there is not disk backing.
		// return;
	}

	if (!get_auxv32(&elf))
	{
		printf("Unable to get auxiliary vectors for pid: %d in collect_results64\n", elf.pid);
	}

	// GET /proc/<pid>/maps.
	if (!collect_maps(elf.pid, &elf.proc_maps_vector))
	{
		printf("Unable to collect /proc/%d/maps in collect_results32\n", elf.pid);
		return;
	}

	// Get LD_PRELOAD, LD_CONFIG, LD_LIBRARY_PATH values from the stack.
	// Only really used for library check, but is very quick, hence included in elf_info.
	if (!get_stack_values(elf.pid, &elf.proc_maps_vector, &elf.stack_variables))
	{
		printf("Unable to collect stack values for pid: %d in collect_results32\n", elf.pid);
		return;
	}

	// Without dynamic segment we can't parse dynamic section info.
	if (elf.elf_mem_hdrs.dynamic_segment_present)
	{
		if (!get_dynamic_info_32(elf.pid, elf.base_vaddr, elf.elf_mem_hdrs.ehdr_mem, elf.elf_mem_hdrs.dyn_pHdr_mem, &elf.elf_mem_hdrs.dyn_info_mem))
		{
			// Failed to read dynamic segment.
			// Add result.
			elf_info_32_vector->push_back(elf);
			return;
		}
	}
	else
	{
		// Dynamic segment not present, no point continuing further.
		printf("No dynamic segment for pid: %d in collect_results32\n", elf.pid);
		// Add result.
		elf_info_32_vector->push_back(elf);
		return;
	}

	////////////////////////////////////////////////////////////////////////
	// All of the below relies on dynamic sections to be parsed correctly //
	////////////////////////////////////////////////////////////////////////

	// This is only used for libcheck.
	resolve_dt_needed_names_32(elf.pid, &elf.elf_mem_hdrs.dyn_info_mem);

	// Get GOT entries for process, tie them with func names from relocation entries.
	if (!get_got_32(elf.pid, elf.elf_mem_hdrs.dyn_info_mem, &elf.elf_mem_hdrs.dyn_info_mem.got_value_vector, &elf.elf_mem_hdrs.dyn_info_mem.link_map_got))
	{
		printf("Unable to find global offset table entries for pid: %d in collect_results32\n", elf.pid);
		// return;
	}

	// Get loaded modules for process
	if (!get_link_map_32(elf.pid, &elf.elf_mem_hdrs.dyn_info_mem))
	{
		printf("Unable to link map for pid: %d in collect_results32\n", elf.pid);
		return;
	}

	// Now collect all the module information.
	for (int j = 0; j < elf.elf_mem_hdrs.dyn_info_mem.link_map.size(); j++)
	{
		// Ignore current process linkMap[j].l_addr == base address of module.
		if (elf.elf_mem_hdrs.dyn_info_mem.link_map[j].l_addr == elf.base_vaddr)
			continue;

		// Ignore modules addresses with no name.
		if (std::string::npos != elf.elf_mem_hdrs.dyn_info_mem.link_map[j].library_name.find("linux-vdso.so"))
			continue;

		// Ignore invalid module addresses
		if ((elf.elf_mem_hdrs.dyn_info_mem.link_map[j].l_addr == 0) || (elf.elf_mem_hdrs.dyn_info_mem.link_map[j].library_name.empty()))
			continue;

		// Is libc used by the process.
		if (std::string::npos != elf.elf_mem_hdrs.dyn_info_mem.link_map[j].library_name.find("libc.so"))
			elf.libc_present = true;

		elf_modules_32 elf_module;

		// Save name an base address in memory.
		elf_module.module_path = elf.elf_mem_hdrs.dyn_info_mem.link_map[j].library_name;
		elf_module.base_vaddr = elf.elf_mem_hdrs.dyn_info_mem.link_map[j].l_addr; // Since it is a SO then this will always be relative to the process base address. e.g. proc_base + module_base = place to read data from

		// Collect disk & memory header information.

		// Need to change this to add destination space for modules, as well as process.
		// Pid, base_vaddr,
		if (!get_headers_and_segment_info_mem_32(elf.pid, elf_module.base_vaddr, &elf_module.elf_mem_hdrs))
		{
			printf("Failed to read module headers for module: %s in pid: %d\n", elf_module.module_path.c_str(), elf.pid);
			continue; // If we fail this move onto the next module to read.
		}

		// Now lets do disk.
		if (!get_headers_and_segment_info_disk_32(elf.pid, elf_module.module_path, &elf_module.elf_disk_hrds, &elf_module.disk_backed))
		{
			printf("Failed to read disk module headers for module: %s in pid: %d\n", elf_module.module_path.c_str(), elf.pid);
			// Still add the result to the output, as we don't need a disk backed info for every scanner.
		}

		// Now collect Dynamic info.
		// Without dynamic segment we can't parse dynamic section info.
		if (elf.elf_mem_hdrs.dynamic_segment_present)
		{
			if (!get_dynamic_info_32(elf.pid, elf_module.base_vaddr, elf_module.elf_mem_hdrs.ehdr_mem, elf_module.elf_mem_hdrs.dyn_pHdr_mem, &elf_module.elf_mem_hdrs.dyn_info_mem))
			{
				// Failed to read dynamic segment.
				printf("Failed to read module dynamic segment for module: %s in pid: %d\n", elf_module.module_path.c_str(), elf.pid);
			}
		}

		// Then push back into modules vector.
		elf.elf_modules.push_back(elf_module);
	}

	// Add result.
	elf_info_32_vector->push_back(elf);
}

void *start_elf_info_thread_32(void *threadarg)
{
	elf_info_thread_data_32 *my_data;
	my_data = (elf_info_thread_data_32 *)threadarg;

	// Print current thead attributes i.e. its policy & priority value.
	// printf("Thread ID: %i started\n", my_data->thread_id);
	// display_thread_sched_attr((char *)"Scheduler attributes of new thread");

	for (auto it = my_data->pid_group.begin(); it != my_data->pid_group.end(); ++it)
	{
		collect_results32((*it), my_data->elf_info_32_vector);
	}

	pthread_exit(NULL);
}

void elf_info_main_32(std::vector<elf_info_32> *elf_info_64_vector, pid_group pidPots)
{
	std::vector<elf_info_32> results_vector[THREAD_COUNT];
	pthread_t threads[THREAD_COUNT];
	elf_info_thread_data_32 td[THREAD_COUNT]; // Thread data needs be changed for specific to scanner results.
	pthread_attr_t attr;
	void *status;
	int rc;
	timespec start_time, end_time;
	time_t elapsed_seconds;
	long elapsed_nanoseconds;

	printf("Starting ELF_INFO collection x86\n");
	clock_gettime(CLOCK_REALTIME, &start_time);

	// Add shellcode results vector.

	// Initialize and set thread attributes (attr) to joinable
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// Make all child threads inherit the same policy & params as the main thread. which has been set above.
	rc = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);

	// Assign a thread to each pidPot (a group of PIDs)
	for (int i = 0; i < THREAD_COUNT; i++)
	{
		td[i].pid_group = pidPots.pid_pots[i];
		td[i].elf_info_32_vector = &results_vector[i];
		td[i].thread_id = i;

		// Create thread sending it to start_elf_info_thread function.
		rc = pthread_create(&threads[i], NULL, start_elf_info_thread_32, (void *)&td[i]);
		if (rc)
		{
			printf("Error:unable to create thread %i\n", rc);
			continue;
		}
	}

	for (int k = 0; k < THREAD_COUNT; k++)
	{
		rc = pthread_join(threads[k], &status);

		if (rc)
		{
			printf("Error:unable to join %i\n", rc);
			continue;
		}

		printf("Completed thread ID: %i.", td[k].thread_id);
		printf("	Exiting with status: %li\n", (long)status);
	}

	// free attribute and wait for the threads to finish.
	pthread_attr_destroy(&attr);

	// Join results vector together, again using some kind of template for different types of results vector for each scanner.
	for (int j = 1; j < THREAD_COUNT; j++)
	{
		results_vector[0].insert(results_vector[0].end(), results_vector[j].begin(), results_vector[j].end());
	}

	// Save elf_info results into elf_info_64_vector.
	*elf_info_64_vector = results_vector[0];

	printf("Elf_info_32_vector size: %lu\n", results_vector[0].size());

	clock_gettime(CLOCK_REALTIME, &end_time);

	elapsed_seconds = end_time.tv_sec - start_time.tv_sec;

	if (end_time.tv_nsec > start_time.tv_nsec)
	{
		elapsed_nanoseconds = end_time.tv_nsec - start_time.tv_nsec;
	}
	else if (start_time.tv_nsec > end_time.tv_nsec)
	{
		elapsed_nanoseconds = start_time.tv_nsec - end_time.tv_nsec;
	}
	else
	{
		elapsed_nanoseconds = 0;
	}

	printf("Finished ELF_INFO collection x86\n");
	printf("ELF_INFO collection x86 runtime: %lu.%lus\n", elapsed_seconds, elapsed_nanoseconds);
}

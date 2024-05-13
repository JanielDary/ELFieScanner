
#include "elf_info.h"

// TODO : Make sure this function is referenced in the header file.
bool read_config(char *config_path, config *my_config)
{

	json j;
	std::ifstream ifs(config_path);

	if (!ifs.is_open())
	{
		printf("Unable to to open config file\n");
		return false;
	}

	// Set ifstream to json
	ifs >> j;

	std::string config_fields[43] =
		{
			// Entry Point scanner checks
			"es_section_hdr_missing",			 // Heuristic 1 : Section headers can been stripped from a binary (this is suspicious but not necessarily malicious). Stripping the section headers makes reverse engineering of the binary more difficult. However it could be done make the binary smaller.
												 // e_shoff This member holds the section header table's file offset in bytes. If the file has no section header table, this member holds zero.
			"es_phdr_wrong_location",			 // Heuristic 2: Check to see if if the program headers start in the expected place (immediately after the ELF32_Ehdr/ELF64_Ehdr) e.g. 64 bytes offset for 64-bit, or 52 bytes offset for 32-bit.
			"es_proc_missing_disk_backing",		 // Heuristic 3: Check the process is not backed by disk executable. More of an anomaly rather than a detection.
			"es_proc_text_segment_missing_disk", // Heuristic 4: Check to see if the .text segment is present on disk. This should always be present unless the binary is still packed/obfuscated in memory.
			"es_proc_text_segment_missing_mem",	 // Heuristic 5: Is the .text segment is present in memory. This should always be present unless the disk backed binary is packed/obfuscated.
			"es_proc_entry_points_not_in_text",	 // Heuristic 6: Check to see if the e_entry field does NOT point within the .text segment. This should always be the case apart from special cases such as ‘VBoxService’.
			"es_proc_entry_points_not_matching", // Heuristic 7: Check to see if the e_entry values for process & disk binary match.
			"es_proc_entry_fuzzy_score",		 // Heuristic 8: Check the e_entry for the libc linked process matches the expected initialization code for ‘libc_start_main’. Highly suspicious unless this is for an interpreter process e.g. ‘/usr/bin/python’ OR container processes ‘/usr/sbin/VBoxService’
			"es_proc_init_fini_not_in_text",	 // Heuristic 9:
												 // process init/fini sections that don't appear in .text segment
												 // process preinit/init/fini array functions that don't point within the .text segment.

			"es_proc_init_not_at_text_start",	// Heuristic 10: For processes it is expected the .init code block should begin at the start of the .text segment. NOTE: this is not expected for modules.
			"es_mod_missing_disk_backing",		// Heuristic 11: Check to see if module is backed by disk executable. More of an anomaly rather than a detection. Check against every module.
			"es_mod_entry_points_not_in_text",	// Heuristic 12: Check the e_entry field points within .text segment of the module. This should always be the case for modules. Check against every module
			"es_mod_entry_points_not_matching", // Heuristic 13: Check to see the e_entry values for module and disk match. Check against every module.
			"es_mod_init_fini_not_in_text",		// Heuristic 14:
												// module init/fini sections that don't appear in .text segment
												// module preinit/init/fini array functions that don't point within the .text segment.
												// Checks against every module.

			// Library scanner checks.
			"ls_elf_in_anonymous_mapping",	   // Heuristic 1 : ELF header found in anonymous memory mapping
			"ls_executable_anonymous_mapping", // Heuristic 2 : Executable anonymous memory mapping
			"ls_phdr_wrong_location",		   // Heuristic 3: Program headers wrong location.
			"ls_mod_missing_disk_backing",	   // Heuristic 4 : Module doesn't have disk backing. Checks for every module.
			"ls_module_not_in_procmaps",	   // Heuristic 5: Module doesn't exist in /proc/<pid>/maps. Checks for every module.
			"ls_module_not_in_linkmap",		   // Heuristic 6: Module doesn't exist in link_map structure. Checks for every module.
			"ls__libc_dlopen_mode_in_got",	   // Heuristic 7: GOT address points __libc_dlopen_mode func.
			"ls__libc_dlopen_mode_in_rodata",  // Heuristic 8: __libc_dlopen_mode string in rodata section.
			"ls_dtnull_missing",			   // Heuristic 9 : DT_NULL missing from dynamic section.
			"ls_dtdebug_missing",			   // Heuristic 10: DT_DEBUG missing from dynamic section
			"ls_dtneeded_incorrect_order",	   // Heuristic 11: DT_NEEDED in non-sequential (incorrect) order in dynamic section
			"ls_dynstr_manipulated",		   // Heuristic 12: Dynamic string table manually manipulated
			"ls_ldpreload_set",				   // Heuristic 13: LD_PRELOAD populated
			"ls_ldpreload_hooking",			   // Heuristic 14: LD_PRELOAD hooking present
			"ls_ldconfig_set",				   // Heuristic 15: LD_CONFIG populated
			"ls_ldpath_set",				   // Heuristic 16: LD_PATH manipulated
			"ls_dynamic_segment_missing",	   // Heuristic 17: Dynamic segment missing

			// Shellcode scanner checks
			"ss_proc_missing_disk_backing",		 // Heuristic 1 : Process missing disk backed binary.
			"ss_proc_phdr_memory_disk_mismatch", // Heuristic 2 : The number of process program headers in memory should equal that of its corresponding disk binary. Any mismatch indicates a segment has either been added or taken away in memory
			"ss_rwx_present_disk",				 // Heuristic 3 : Process memory contains a segment with Read/write & execute permissions.
			"ss_rwx_present_mem",				 // Heuristic 4 : Process binary contains a segment with Read/write & execute permissions.
			"ss_dynamic_segment_missing",		 // Heuristic 5 : Dynamic segment missing. Can indicate packing.
			"ss_memfd_mapping_found",			 // Heuristic 6 : Process loaded directly from memory using memfd_create()
			"ss_mod_missing_disk_backing",		 // Heuristic 7 : module missing disk backed binary. Check for all modules
			"ss_mod_phdr_memory_disk_mismatch",	 // Heuristic 9: The number of module program headers in memory should equal that of its corresponding disk binary. Any mismatch indicates a segment has either been added or taken away in memory. Check for all modules.
			"ss_mod_rwx_header_present_disk",	 // Heuristic 3 : Module memory contains a segment with Read/write & execute permissions. Check for all modules.
			"ss_mod_rwx_header_present_mem",	 // Heuristic 4 : Module binary contains a segment with Read/write & execute permissions. Check for all modules.
			"ss_proc_score",					 // Heuristic 11: This measures the similarity between process disk & memory text (RX) segments. A low score indicates significant changes (and thus possible injection of code).
			"ss_lowest_mod_score",				 // Heuristic 12: This measures the similarity between module disk & memory text (RX) segments. A low score indicates significant changes (and thus possible injection of code).
		};

	// Verify all fields are present in supplied config file.
	for (int i = 0; i < 43; i++)
	{
		if (j.find(config_fields[i]) == j.end())
		{
			// Not all fields present in config file
			printf("Config file format incorrect!\n");
			return false;
		}
	}

	// Populate entry point config struct with settings.
	my_config->es_section_hdr_missing = j.at("es_section_hdr_missing");
	my_config->es_phdr_wrong_location = j.at("es_phdr_wrong_location");
	my_config->es_proc_missing_disk_backing = j.at("es_proc_missing_disk_backing");
	my_config->es_proc_text_segment_missing_disk = j.at("es_proc_text_segment_missing_disk");
	my_config->es_proc_text_segment_missing_mem = j.at("es_proc_text_segment_missing_mem");
	my_config->es_proc_entry_points_not_in_text = j.at("es_proc_entry_points_not_in_text");
	my_config->es_proc_entry_points_not_matching = j.at("es_proc_entry_points_not_matching");
	my_config->es_proc_entry_fuzzy_score = j.at("es_proc_entry_fuzzy_score");
	my_config->es_proc_init_fini_not_in_text = j.at("es_proc_init_fini_not_in_text");
	my_config->es_proc_init_not_at_text_start = j.at("es_proc_init_not_at_text_start");
	my_config->es_mod_missing_disk_backing = j.at("es_mod_missing_disk_backing");
	my_config->es_mod_entry_points_not_in_text = j.at("es_mod_entry_points_not_in_text");
	my_config->es_mod_entry_points_not_matching = j.at("es_mod_entry_points_not_matching");
	my_config->es_mod_init_fini_not_in_text = j.at("es_mod_init_fini_not_in_text");

	// Populate library scanner config with settings.
	my_config->ls_elf_in_anonymous_mapping = j.at("ls_elf_in_anonymous_mapping");
	my_config->ls_executable_anonymous_mapping = j.at("ls_executable_anonymous_mapping");
	my_config->ls_phdr_wrong_location = j.at("ls_phdr_wrong_location");
	my_config->ls_mod_missing_disk_backing = j.at("ls_mod_missing_disk_backing");
	my_config->ls_module_not_in_procmaps = j.at("ls_module_not_in_procmaps");
	my_config->ls_module_not_in_linkmap = j.at("ls_module_not_in_linkmap");
	my_config->ls__libc_dlopen_mode_in_got = j.at("ls__libc_dlopen_mode_in_got");
	my_config->ls__libc_dlopen_mode_in_rodata = j.at("ls__libc_dlopen_mode_in_rodata");
	my_config->ls_dtnull_missing = j.at("ls_dtnull_missing");
	my_config->ls_dtdebug_missing = j.at("ls_dtdebug_missing");
	my_config->ls_dtneeded_incorrect_order = j.at("ls_dtneeded_incorrect_order");
	my_config->ls_dynstr_manipulated = j.at("ls_dynstr_manipulated");
	my_config->ls_ldpreload_set = j.at("ls_ldpreload_set");
	my_config->ls_ldpreload_hooking = j.at("ls_ldpreload_hooking");
	my_config->ls_ldconfig_set = j.at("ls_ldconfig_set");
	my_config->ls_ldpath_set = j.at("ls_ldpath_set");
	my_config->ls_dynamic_segment_missing = j.at("ls_dynamic_segment_missing");

	// Populate shellcode scanner config with settings.
	my_config->ss_proc_missing_disk_backing = j.at("ss_proc_missing_disk_backing");
	my_config->ss_proc_phdr_memory_disk_mismatch = j.at("ss_proc_phdr_memory_disk_mismatch");
	my_config->ss_rwx_present_disk = j.at("ss_rwx_present_disk");
	my_config->ss_rwx_present_mem = j.at("ss_rwx_present_mem");
	my_config->ss_dynamic_segment_missing = j.at("ss_dynamic_segment_missing");
	my_config->ss_memfd_mapping_found = j.at("ss_memfd_mapping_found");
	my_config->ss_mod_missing_disk_backing = j.at("ss_mod_missing_disk_backing");
	my_config->ss_mod_phdr_memory_disk_mismatch = j.at("ss_mod_phdr_memory_disk_mismatch");
	my_config->ss_mod_rwx_header_present_disk = j.at("ss_mod_rwx_header_present_disk");
	my_config->ss_mod_rwx_header_present_mem = j.at("ss_mod_rwx_header_present_mem");
	my_config->ss_proc_score = j.at("ss_proc_score");
	my_config->ss_lowest_mod_score = j.at("ss_lowest_mod_score");

	return true;
}

bool collect_maps(pid_t pid, std::vector<single_procmap_struct> *proc_maps_vector)
{
	procmaps_iterator *maps = pmparser_parse(pid);
	if (maps == NULL)
	{
		printf("[map]: cannot parse the memory map of %d\n", pid);
		return false;
	}

	procmaps_struct *maps_tmp = NULL;
	while ((maps_tmp = pmparser_next(maps)) != NULL)
	{
		single_procmap_struct mapping;

		mapping.addr_start = maps_tmp->addr_start;
		mapping.addr_end = maps_tmp->addr_end;
		mapping.length = maps_tmp->length;

		strcpy(mapping.perm, maps_tmp->perm);
		mapping.is_r = maps_tmp->is_r;
		mapping.is_w = maps_tmp->is_w;
		mapping.is_x = maps_tmp->is_x;
		mapping.is_p = maps_tmp->is_p;

		mapping.offset = maps_tmp->offset;
		strcpy(mapping.dev, maps_tmp->dev);
		mapping.inode = maps_tmp->inode;
		strcpy(mapping.pathname, maps_tmp->pathname);

		proc_maps_vector->push_back(mapping);
		free(maps_tmp);
	}

	// Reset iterator to point at the start again.
	// maps->current = maps->head;

	free(maps);
	return true;
}

void resolve_dt_needed_names_64(pid_t pid, dynamic_info64 *dyn_info)
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

bool get_stack_values(int pid, std::vector<single_procmap_struct> *proc_maps_vector, stack_vars *stackVariables)
{
	char buff[4096];
	// LD_PRELOAD=
	char a[] = {0x4c, 0x44, 0x5f, 0x50, 0x52, 0x45, 0x4c, 0x4f, 0x41, 0x44, 0x3d};
	// LD_LIBRARY_PATH=
	char b[] = {0x4c, 0x44, 0x5f, 0x4c, 0x49, 0x42, 0x52, 0x41, 0x52, 0x59, 0x5f, 0x50, 0x41, 0x54, 0x48, 0x3d};
	// LD_CONFIG
	char c[] = {0x4c, 0x44, 0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x3d};

	int distance = 0;

	for (std::vector<single_procmap_struct>::iterator it = proc_maps_vector->begin(); it != proc_maps_vector->end(); ++it)
	{
		if (strcmp((*it).pathname, "[stack]") == 0)
		{
			// Read the first 4096 bytes (page) from the stack
			// Environ Variables likely to be at the bottom of the stack. I.e. the highest address
			uint64_t readFrom = (uint64_t)(*it).addr_end;
			readFrom -= 0x1000;

			if (process_read(pid, buff, (void *)readFrom, 4096) == -1)
			{
				printf("Failed to read first 4096 bytes of stack from /proc/%i/maps using process_read(): %s\n", pid, strerror(errno));
				return false;
			}
			else
			{
				auto ir = std::search(
					std::begin(buff), std::end(buff),
					std::begin(a), std::end(a));

				if (ir != std::end(buff))
				{
					// subrange found at distance into buff
					distance = std::distance(std::begin(buff), ir);
					// store value of LD_PRELOAD (+11 to skip passed LD_PRELOAD= characters)
					std::string ld_preload = (char *)(buff + distance + 11);
					stackVariables->ld_preload = sanitize_string(ld_preload);
					stackVariables->ld_preload_present = true;
				}

				auto id = std::search(
					std::begin(buff), std::end(buff),
					std::begin(b), std::end(b));

				if (id != std::end(buff))
				{
					distance = std::distance(std::begin(buff), id);
					// store value of LD_LIBRARY_PATH= (+16 to skip passed name)
					std::string ld_path = (char *)(buff + distance + 16);
					stackVariables->ld_path = sanitize_string(ld_path);
					stackVariables->ld_path = true;
				}

				auto is = std::search(
					std::begin(buff), std::end(buff),
					std::begin(c), std::end(c));

				if (is != std::end(buff))
				{
					distance = std::distance(std::begin(buff), is);
					// store value of LD_CONFIG= (+10 to skip passed name)
					std::string ld_config = (char *)(buff + distance + 10);
					stackVariables->ld_config = sanitize_string(ld_config);
					stackVariables->ld_config = true;
				}
			}
		}
	}

	return true;
}

void generate_elf_info_64_pots(std::vector<elf_info_64> *elf_info_vector, elf_info_64_group *elf_info_groups)
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
			elf_info_groups->elf_info_64_pots[i].push_back(*it);
			counter++;
			continue;
		}
		else if (counter % potSize == 0)
		{
			i++; // Start a new group
		}

		elf_info_groups->elf_info_64_pots[i].push_back(*it);
		counter++;
	}
}

bool get_auxv64(elf_info_64 *elf)
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
	Elf64_auxv_t *auxv = NULL;

	for (auxv = (Elf64_auxv_t *)auxv_buffer; auxv->a_type != AT_NULL && (char *)auxv < auxv_buffer + result; ++auxv)
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

bool get_headers_and_segment_info_mem_64(pid_t pid, Elf64_Addr base_vaddr, elf_mem_hdrs_64 *elf_mem_hdrs)
{

	uint8_t *pmem;
	Elf64_Phdr *phdr;

	if (process_read(pid, (void *)&elf_mem_hdrs->ehdr_mem, (void *)base_vaddr, sizeof(Elf64_Ehdr)) == -1)
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

	pmem = (uint8_t *)alloca(sizeof(Elf64_Ehdr) + (elf_mem_hdrs->ehdr_mem.e_phentsize * elf_mem_hdrs->ehdr_mem.e_phnum));

	/* Read in just the ehdr & phdrs and get the exact size of segments
	if (process_read(pid, pmem, (void *)base_vaddr, (sizeof(Elf64_Ehdr) + ehdr.e_phentsize * ehdr.e_phnum)) == -1)
	{
		printf("Failed to read Program headers with process_read() in function get_headers_and_segment_info: %s\n from pid: %i", strerror(errno), pid);
		return false;
	}
	*/

	if ((base_vaddr + sizeof(Elf64_Ehdr)) != (base_vaddr + elf_mem_hdrs->ehdr_mem.e_phoff))
	{
		// phdrs should start immediately after the ehdrs. This means they don't!
		// Headers are in non-standard place, indicating manipulation (as with more sophisticated DT_NEEDED infections)
		// Make sure we print out DT_NEEDED entries from here.
		elf_mem_hdrs->phdr_irregular_location_mem = true;
	}

	// Read in just the ehdr & phdrs and get the exact size of segments
	if (process_read(pid, pmem, (void *)(base_vaddr + elf_mem_hdrs->ehdr_mem.e_phoff), (elf_mem_hdrs->ehdr_mem.e_phentsize * elf_mem_hdrs->ehdr_mem.e_phnum)) == -1)
	{
		printf("Failed to read Program headers with process_read() in function get_headers_and_segment_info: %s\n from pid: %i", strerror(errno), pid);
		return false;
	}

	// First entry phdr[0] is entry for header table itself
	// phdr = (Elf64_Phdr *)(pmem + ehdr.e_phoff);
	phdr = (Elf64_Phdr *)pmem;

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

bool get_headers_and_segment_info_disk_64(pid_t pid, std::string file_name, elf_disk_hrds_64 *elf_disk_hdrs, bool *disk_backed)
{
	int fd;
	struct stat st;
	// Elf64_Ehdr * ehdr;
	Elf64_Phdr *phdr;
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
	elf_disk_hdrs->ehdr_disk = *(Elf64_Ehdr *)mem;

	// We don't need to keep pHdr for disk. So Just use it to enumerate segments we care about.
	phdr = (Elf64_Phdr *)&mem[elf_disk_hdrs->ehdr_disk.e_phoff];

	// Check to see if phdrs start directly after ehdrs
	if (sizeof(Elf64_Ehdr) != elf_disk_hdrs->ehdr_disk.e_phoff)
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

bool get_dynamic_info_64(pid_t pid, Elf64_Addr base_vaddr, Elf64_Ehdr ehdr_mem, Elf64_Phdr dyn_pHdr_mem, dynamic_info64 *dyn_info_mem)
{
	uint8_t *dynSegmentMem;
	Elf64_Dyn *dyn;
	bool endOfDyn = false;

	dynSegmentMem = (uint8_t *)alloca(dyn_pHdr_mem.p_memsz);

	// Get Dynamic segment
	// Executables (ET_EXEC) always use the same base address hence the dynamic segment address will be absolute.
	// Shared object (ET_DYN) compiled executables use relative addressing. So the base address needs to be added.
	if (ehdr_mem.e_type == ET_EXEC)
	{
		if (process_read(pid, dynSegmentMem, (void *)(dyn_pHdr_mem.p_vaddr), dyn_pHdr_mem.p_memsz) == -1)
		{
			printf("Failed to read Dynamic segment into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
			return false;
		}
	}
	else if (ehdr_mem.e_type == ET_DYN)
	{
		if (process_read(pid, dynSegmentMem, (void *)(base_vaddr + dyn_pHdr_mem.p_vaddr), dyn_pHdr_mem.p_memsz) == -1)
		{
			printf("Failed to read Dynamic segment into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
			return false;
		}
	}

	// dyn = (Elf64_Dyn *)dynSegmentMem;
	dyn = (Elf64_Dyn *)dynSegmentMem;

	// Number of dynamic entries
	int numberof_DynEntries = (dyn_pHdr_mem.p_memsz / sizeof(Elf64_Dyn));

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
			dyn_info_mem->got_entries = dyn_info_mem->dt_pltrelsz / sizeof(Elf64_Rel);
		}
		else if (dyn_info_mem->dt_pltrel == DT_RELA)
		{
			dyn_info_mem->got_entries = dyn_info_mem->dt_pltrelsz / sizeof(Elf64_Rela);
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

bool get_got_64(pid_t pid, dynamic_info64 dyn_info, std::vector<got_value_64> *got_value_vector, ElfW(Addr) * link_map_got)
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
	Elf64_Addr *GLOBAL_OFFSET_TABLE;
	got_value_64 got_entry;

	// If there is no pltgot, pltrel OR got_entries then quit.
	if ((dyn_info.got_entries == 0) || (!dyn_info.dt_pltgot_present) || (!dyn_info.dt_pltrel_present))
	{
		return false;
	}

	// Allocate buffer on stack to store size of GOT
	got_mem = (uint8_t *)alloca((dyn_info.got_entries * sizeof(Elf64_Addr)));

	// Get GOT - .plt.got is in the DATA segment
	if (process_read(pid, got_mem, (void *)dyn_info.dt_pltgot, (dyn_info.got_entries * sizeof(Elf64_Addr))) == -1)
	{
		printf("Failed to read GOT table with process_read() in function got_got: %s\n", strerror(errno));
		return false;
	}

	GLOBAL_OFFSET_TABLE = (Elf64_Addr *)got_mem;

	// Skip the first three addresses (8 bytes each for 64-bit, 24 bytes total).
	int func_offset = sizeof(Elf64_Addr) * 3;

	// link_map location
	*link_map_got = GLOBAL_OFFSET_TABLE[1];

	// We are skipping the first three entries
	for (int j = 3; j < dyn_info.got_entries; j++)
	{
		got_entry.GOT_entry_number = j;
		got_entry.vaddr_of_entry = dyn_info.dt_pltgot + func_offset;
		got_entry.func_pointer = (Elf64_Addr)GLOBAL_OFFSET_TABLE[j];
		got_value_vector->push_back(got_entry);
		func_offset += sizeof(Elf64_Addr); // Increment to next address (8bytes for x64, 4 bytes for x86)
	}

	return true;
}

bool get_link_map_64(pid_t pid, dynamic_info64 *dyn_info)
{
	Elf64_Addr link_map_location;
	r_debug debugSection;

	if (dyn_info->dt_debug_present)
	{
		if (process_read(pid, &debugSection, (const void *)dyn_info->dt_debug, sizeof(r_debug)))
		{
			printf("Failed to read r_debug with process_read() in function get_link_map_64: %s for pid: %i\n", strerror(errno), pid);
			return false;
		}
		else
		{
			link_map_location = (Elf64_Addr)debugSection.r_map;
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

	custom_link_map_64 link_map_entry;
	std::vector<uint64_t> forward_pointer;

	// Read first link_map struct from mem.
	if (process_read(pid, &link_map_entry, (const void *)link_map_location, sizeof(link_map)))
	{
		printf("Failed to read link_map with process_read() in function get_link_map_64: %s for pid: %i\n", strerror(errno), pid);
		return false;
	}
	else
	{
		link_map_entry.library_name = get_mod_name(pid, (Elf64_Addr)link_map_entry.l_name);

		// link_map->push_back(link_map_entry);
		dyn_info->link_map.push_back(link_map_entry);

		forward_pointer.push_back(link_map_location);

		// Check to see if the next item in the linked list is zero of an element we have already seen.
		while ((!contains(forward_pointer, (uint64_t)link_map_entry.l_next)) && link_map_entry.l_next != nullptr)
		{
			forward_pointer.push_back((uint64_t)link_map_entry.l_next);

			if (process_read(pid, &link_map_entry, (const void *)link_map_entry.l_next, sizeof(link_map)))
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

void collect_results64(pid_t pid, std::vector<elf_info_64> *elf_info_64_vector)
{
	// Malloc is threadsafe on glibc-2.2+ & x86 & AMD64 when using -phread.
	// https://stackoverflow.com/questions/855763/is-malloc-thread-safe

	elf_info_64 elf;

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
	if (!get_headers_and_segment_info_mem_64(elf.pid, elf.base_vaddr, &elf.elf_mem_hdrs))
	{
		printf("Failed to read process headers for pid: %d in collect_results64\n", elf.pid);
		return;
	}

	if (!get_headers_and_segment_info_disk_64(elf.pid, elf.process_path, &elf.elf_disk_hdrs, &elf.disk_backed))
	{
		printf("Failed to read disk headers for pid: %d in collect_results64\n", elf.pid);
		// Maybe we should continue if there is not disk backing.
		// return;
	}

	if (!get_auxv64(&elf))
	{
		printf("Unable to get auxiliary vectors for pid: %d in collect_results64\n", elf.pid);
	}

	// GET /proc/<pid>/maps.
	if (!collect_maps(elf.pid, &elf.proc_maps_vector))
	{
		printf("Unable to collect /proc/%d/maps in collect_results64\n", elf.pid);
		return;
	}

	// Get LD_PRELOAD, LD_CONFIG, LD_LIBRARY_PATH values from the stack.
	// Only really used for library check, but is very quick, hence included in elf_info.
	if (!get_stack_values(elf.pid, &elf.proc_maps_vector, &elf.stack_variables))
	{
		printf("Unable to collect stack values for pid: %d in collect_results64\n", elf.pid);
		return;
	}

	// Without dynamic segment we can't parse dynamic section info.
	if (elf.elf_mem_hdrs.dynamic_segment_present)
	{
		if (!get_dynamic_info_64(elf.pid, elf.base_vaddr, elf.elf_mem_hdrs.ehdr_mem, elf.elf_mem_hdrs.dyn_pHdr_mem, &elf.elf_mem_hdrs.dyn_info_mem))
		{
			// Failed to read dynamic segment.
			// Add result.
			elf_info_64_vector->push_back(elf);
			return;
		}
	}
	else
	{
		// Dynamic segment not present, no point continuing further.
		printf("No dynamic segment for pid: %d in collect_results64\n", elf.pid);
		// Add result.
		elf_info_64_vector->push_back(elf);
		return;
	}

	////////////////////////////////////////////////////////////////////////
	// All of the below relies on dynamic sections to be parsed correctly //
	////////////////////////////////////////////////////////////////////////

	// This is only used for libcheck.
	resolve_dt_needed_names_64(elf.pid, &elf.elf_mem_hdrs.dyn_info_mem);

	// Get GOT entries for process, tie them with func names from relocation entries.
	if (!get_got_64(elf.pid, elf.elf_mem_hdrs.dyn_info_mem, &elf.elf_mem_hdrs.dyn_info_mem.got_value_vector, &elf.elf_mem_hdrs.dyn_info_mem.link_map_got))
	{
		printf("Unable to find global offset table entries for pid: %d in collect_results64\n", elf.pid);
		// return;
	}

	// Get loaded modules for process
	if (!get_link_map_64(elf.pid, &elf.elf_mem_hdrs.dyn_info_mem))
	{
		printf("Unable to link map for pid: %d in collect_results64\n", elf.pid);
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

		elf_modules_64 elf_module;

		// Save name an base address in memory.
		elf_module.module_path = elf.elf_mem_hdrs.dyn_info_mem.link_map[j].library_name;
		elf_module.base_vaddr = elf.elf_mem_hdrs.dyn_info_mem.link_map[j].l_addr; // Since it is a SO then this will always be relative to the process base address. e.g. proc_base + module_base = place to read data from

		// Collect disk & memory header information.

		// Need to change this to add destination space for modules, as well as process.
		// Pid, base_vaddr,
		if (!get_headers_and_segment_info_mem_64(elf.pid, elf_module.base_vaddr, &elf_module.elf_mem_hdrs))
		{
			printf("Failed to read module headers for module: %s in pid: %d\n", elf_module.module_path.c_str(), elf.pid);
			continue; // If we fail this move onto the next module to read.
		}

		// Now lets do disk.
		if (!get_headers_and_segment_info_disk_64(elf.pid, elf_module.module_path, &elf_module.elf_disk_hrds, &elf_module.disk_backed))
		{
			printf("Failed to read disk module headers for module: %s in pid: %d\n", elf_module.module_path.c_str(), elf.pid);
			// Still add the result to the output, as we don't need a disk backed info for every scanner.
		}

		// Now collect Dynamic info.
		// Without dynamic segment we can't parse dynamic section info.
		if (elf.elf_mem_hdrs.dynamic_segment_present)
		{
			if (!get_dynamic_info_64(elf.pid, elf_module.base_vaddr, elf_module.elf_mem_hdrs.ehdr_mem, elf_module.elf_mem_hdrs.dyn_pHdr_mem, &elf_module.elf_mem_hdrs.dyn_info_mem))
			{
				// Failed to read dynamic segment.
				printf("Failed to read module dynamic segment for module: %s in pid: %d\n", elf_module.module_path.c_str(), elf.pid);
			}
		}

		// Then push back into modules vector.
		elf.elf_modules.push_back(elf_module);
	}

	// Add result.
	elf_info_64_vector->push_back(elf);
}

void *start_elf_info_thread_64(void *threadarg)
{
	elf_info_thread_data_64 *my_data;
	my_data = (elf_info_thread_data_64 *)threadarg;

	// Print current thead attributes i.e. its policy & priority value.
	// printf("Thread ID: %i started\n", my_data->thread_id);
	// display_thread_sched_attr((char *)"Scheduler attributes of new thread");

	for (auto it = my_data->pid_group.begin(); it != my_data->pid_group.end(); ++it)
	{
		collect_results64((*it), my_data->elf_info_64_vector);
	}

	pthread_exit(NULL);
}

void elf_info_main_64(std::vector<elf_info_64> *elf_info_64_vector, pid_group pidPots)
{
	std::vector<elf_info_64> results_vector[THREAD_COUNT];
	pthread_t threads[THREAD_COUNT];
	elf_info_thread_data_64 td[THREAD_COUNT]; // Thread data needs be changed for specific to scanner results.
	pthread_attr_t attr;
	void *status;
	int rc;
	timespec start_time, end_time;
	time_t elapsed_seconds;
	long elapsed_nanoseconds;

	printf("Starting ELF_INFO collection x64\n");
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
		td[i].elf_info_64_vector = &results_vector[i];
		td[i].thread_id = i;

		// Create thread sending it to start_elf_info_thread function.
		rc = pthread_create(&threads[i], NULL, start_elf_info_thread_64, (void *)&td[i]);
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

	printf("Elf_info_64_vector size: %lu\n", results_vector[0].size());

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

	printf("Finished ELF_INFO collection x64\n");
	printf("ELF_INFO collection x64 runtime: %lu.%lus\n", elapsed_seconds, elapsed_nanoseconds);
}


#include "library_scanner.h"

void get_symbol_info_32(pid_t pid, dynamic_info32 *dynamic_info, Elf64_Addr base_vaddr, std::vector<symbol_info> *symbol_info_vector, std::string module_name, bool extract_only_symbols_with_data)
{
	/* Function description :
		1. Ascertains size of symbol table for module, either by looking in DT_GNU_HASH section or DT_HASH. 
		2. Parses symbols in symbol table collecting:
			(i):   Module name
			(ii):  Address of symbol in module
			(iii): Symbol name
	*/

	symbol_info symbol_entry;
	uint32_t number_of_symbols = 0;
	std::string function_name;

	if (dynamic_info->dt_gnu_hash_present)
	{
		number_of_symbols = parse_gnu_hash_table(pid, base_vaddr, dynamic_info->dt_gnu_hash);
	}
	else if (dynamic_info->dt_hash_present)
	{

		if (dynamic_info->dt_hash < base_vaddr)
		{
			dynamic_info->dt_hash += base_vaddr;
		}

		// If no DT_GNU_HASH table, then read DT_HASH table.
		partial_hash_table *hash_table = (partial_hash_table *)alloca(sizeof(partial_hash_table));

		if (process_read(pid, (void *)hash_table, (void *)(uint64_t)dynamic_info->dt_hash, sizeof(partial_hash_table)) == -1)
		{
			printf("Failed to read hash table into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
			return;
		}
		else
		{
			number_of_symbols = hash_table->nchain;
		}
	}
	else
	{
		printf("Unable to find any HashTable for module, thus can't resolve symbols  for pid: %i\n", pid);
		return;
	}

	char *strtab_mem = (char *)calloc(1, dynamic_info->dt_strsz);
	Elf64_Sym *symtab_mem = (Elf64_Sym *)calloc((dynamic_info->dt_syment * number_of_symbols), sizeof(Elf64_Sym));

	// Check to see if our dynInfo->strtab address already includes a base_vaddr.
	if (dynamic_info->dt_symtab < base_vaddr)
	{
		dynamic_info->dt_symtab += base_vaddr;
	}

	// Read whole symbol table
	if (process_read(pid, (void *)symtab_mem, (void *)(uint64_t)dynamic_info->dt_symtab, (dynamic_info->dt_syment * number_of_symbols)) == -1)
	{
		printf("Failed to read symtab in get_symbol_info function with process_read(): %s for pid: %i\n", strerror(errno), pid);
		free(strtab_mem);
		free(symtab_mem);
		return;
	}

	if (dynamic_info->dt_strtab < base_vaddr)
	{
		dynamic_info->dt_strtab += base_vaddr;
	}
	// Read whole string table.
	if (process_read(pid, (void *)strtab_mem, (void *)(uint64_t)dynamic_info->dt_strtab, dynamic_info->dt_strsz) == -1)
	{
		printf("Failed to read strtab into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
		free(strtab_mem);
		free(symtab_mem);
		return;
	}

	// Loop through symbol table entries, missing first entry because it is NULL. (STN_UNDEF symbol at 0 index)
	for (int i = 1; i < number_of_symbols; i++)
	{

		int symbol_binding = 0;
		int symbol_type = 0;

		symbol_binding = ELF32_ST_BIND(symtab_mem[i].st_info);
		symbol_type = ELF32_ST_TYPE(symtab_mem[i].st_info);

		// We are only intrested symbols which relate to exported functions.
		if ((symbol_type != STT_FUNC) && (symbol_type != STT_NOTYPE))
			continue;

		if ((symbol_binding != STB_GLOBAL) && (symbol_binding != STB_WEAK))
			continue;

		// Look for symbols with data, rather than just references in preloaded libraries
		if (extract_only_symbols_with_data)
		{
			if (symtab_mem[i].st_size < 1)
				continue;
		}

		symbol_entry.module_path = module_name;
		symbol_entry.func_addr = symtab_mem[i].st_value + base_vaddr;
		int index = (int)symtab_mem[i].st_name;

		char *tmp_func_name = strtab_mem + index;
		function_name = tmp_func_name;
		symbol_entry.func_name = sanitize_string(function_name);
		symbol_info_vector->push_back(symbol_entry);
	}

	free(strtab_mem);
	free(symtab_mem);

	return;
}

void get_jump_entry_relocations_32(pid_t pid, dynamic_info32 *dynamic_info, Elf64_Addr base_vaddr, std::vector<got_value_32> *got_values_vector)
{
	/* Function description :
		1. Records relocations of type R_X86_64_JUMP_SLOT. 
		2. Records the address at which the locations are resolved, which can be used to match up corresponding GOT entries. 
		3. Records the intended function name the relocation should point to. 


	This func is inefficient, it reads one entry from symtab at a time. So we don't need to find size of symtab.
	Could check to see if index_into_symtab increases sequentially from the first relocation entry.
	If it does, then we can change this func so it only reads in symtab once.
	Alternatively we could read all indexes :-
		Find the largest index
		Find the length to the next page boundary
		Use this to calculate how many pages we can saftely read at once
		This mem will effectively contain the whole symtab we need for rest of function.
	*/

	// Check for dt_rel type e.g. ELF64_Rela vs ELF64_Rel.

	// Check to see if we have any got values first.
	if (got_values_vector->empty())
	{
		printf("No GOT values found for pid: %i, skipping get_jump_entry_relocations32\n", pid);
		return;
	}

	Elf32_Addr offset;
	Elf32_Word r_info;
	uint32_t index_into_strtab;
	int number_of_relocation_entries;

	void *relocation_entries_mem;

	if (dynamic_info->dt_pltrel == DT_RELA)
	{
		number_of_relocation_entries = dynamic_info->dt_pltrelsz / sizeof(Elf32_Rela);
		relocation_entries_mem = calloc(sizeof(Elf32_Rela), (size_t)dynamic_info->dt_pltrelsz);
	}
	else if (dynamic_info->dt_pltrel == DT_REL)
	{
		number_of_relocation_entries = dynamic_info->dt_pltrelsz / sizeof(Elf32_Rel);
		relocation_entries_mem = calloc(sizeof(Elf32_Rel), (size_t)dynamic_info->dt_pltrelsz);
	}
	else
	{
		printf("Unable to determine relocation table entry size for pid:%i \n", pid);
		return;
	}

	// We ned to figure out how to deal with different REL / RELA here. Could split into if else statements.
	// Allocate memory before reading something new, otherwise it can corrupt/overwrite locations.
	// Elf64_Rela *relocation_entries = (Elf64_Rela *)calloc(sizeof(Elf64_Rela), (size_t)dynamic_info->dt_pltrelsz);

	Elf32_Sym *symtab_mem = (Elf32_Sym *)calloc(sizeof(Elf32_Sym), (size_t)dynamic_info->dt_syment); // one entry.
	char *strtab_mem = (char *)calloc(sizeof(char), dynamic_info->dt_strsz);

	// Check if dynamic_info->dt_jmprel is relative of absoutel address.
	Elf32_Addr dt_jmprel_address = (base_vaddr > dynamic_info->dt_jmprel) ? (base_vaddr + dynamic_info->dt_jmprel) : dynamic_info->dt_jmprel;

	if (process_read(pid, (void *)relocation_entries_mem, (void *)(uint64_t)dt_jmprel_address, dynamic_info->dt_pltrelsz) == -1)
	{
		printf("Failed to read relocation table into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
		goto fail;
	}

	// Parse relocation Entries for GOT
	for (int i = 0; i < number_of_relocation_entries; i++)
	{

		int32_t index_into_symtab;
		int32_t relocation_type;

		if (dynamic_info->dt_pltrel == DT_RELA)
		{
			// Cast to correct type based on dt_pltrel value.
			Elf32_Rela *relocation_entries = reinterpret_cast<Elf32_Rela *>(relocation_entries_mem);

			offset = relocation_entries[i].r_offset; // For an executable or shared objects r_offset indicates the virtual address of the storage unit affected by the relocation.
			r_info = relocation_entries[i].r_info;	 // Relocation type and symbol index.

			index_into_symtab = ELF32_R_SYM(r_info); // Macro to calculate symbol index.
			relocation_type = ELF32_R_TYPE(r_info);	 // Macro to calculate relocation type.

			// We ignore the r_addend field because it only exists in DT_RELA
		}
		else if (dynamic_info->dt_pltrel == DT_REL)
		{
			// Cast to correct type based on dt_pltrel value.
			Elf32_Rel *relocation_entries = reinterpret_cast<Elf32_Rel *>(relocation_entries_mem);

			offset = relocation_entries[i].r_offset;
			r_info = relocation_entries[i].r_info;

			index_into_symtab = ELF32_R_SYM(r_info);
			relocation_type = ELF32_R_TYPE(r_info);
		}

		// Expected to be in relocation table however, the offsets and attend field don't point to a string table entry instead they point to a ifunc.
		// See https://stackoverflow.com/questions/17404672/what-does-r-x86-64-irelativ-mean
		if (relocation_type == R_X86_64_IRELATIVE)
		{
			continue;
		}

		// Relocation type should always be of type R_X86_64_JUMP_SLOT!
		if (!(relocation_type == R_X86_64_JUMP_SLOT))
		{
			// printf("Relocation type is not of type R_X86_64_JUMP_SLOT or R_X86_64_IRELATIVE  for pid: %i\n", pid);
			// goto fail;
			continue;
		}

		Elf32_Addr symtab_readfrom = (uint32_t)dynamic_info->dt_symtab + (dynamic_info->dt_syment * index_into_symtab);

		if (process_read(pid, (void *)symtab_mem, (void *)(uint64_t)symtab_readfrom, dynamic_info->dt_syment) == -1)
		{
			printf("Failed to read symtab into memory with process_read(): %s  for pid: %i\n", strerror(errno), pid);
			goto fail;
		}

		index_into_strtab = symtab_mem->st_name; // Index into strtab section, entries start at 0, hence the -1.

		Elf32_Addr strtab_readfrom = (uint32_t)dynamic_info->dt_strtab + (uint32_t)index_into_strtab;

		// Read entry.
		if (process_read(pid, (void *)strtab_mem, (void *)(uint64_t)strtab_readfrom, dynamic_info->dt_strsz - index_into_strtab) == -1)
		{
			printf("Failed to read strtab into memory with process_read(): %s for pid %i\n", strerror(errno), pid);
			goto fail;
		}

		// Skip first three entries, because these are reserved values.
		// remove +3 since we aren't collecting them anymore.
		(*got_values_vector)[i].vaddr_of_reloc = (offset + base_vaddr);
		(*got_values_vector)[i].legit_reloc_func_name = strtab_mem;
	}

	free(relocation_entries_mem);
	free(symtab_mem);
	free(strtab_mem);
	return;

fail:
	free(relocation_entries_mem);
	free(symtab_mem);
	free(strtab_mem);
	return;
}

void check_preload_hooking_32(elf_info_32 *elf_info, library_results *result, std::vector<got_value_32> imports_vector)
{

	std::vector<symbol_info> preload_symbol_info_vector, symbol_info_vector;
	bool preload_libraries_in_link_map = false;
	std::vector<std::string> preload_libraries_vector;

	// The dynamic linker is smart enough to recognize copies of existing libraries. For instance if my_libc is preloaed instead of regular libc but they are both the exactly the same, then only my_libc will be included in the link_map.
	// Hence it won't load the regular libc at all.

	get_preload_libraries(elf_info->stack_variables.ld_preload, &preload_libraries_vector);

	// Get Symbols for preloaded & non-preloaded libraries.
	// Check to see if preloaded libraries exist first, otherwise there is no point in collecting symbols to look for function hooking.
	if (!preload_libraries_vector.empty())
	{
		// Preloaded libraries are uncommon anyway so include this in output.
		result->preloaded_libraries = preload_libraries_vector;

		if (!elf_info->elf_modules.empty())
		{
			for (auto modules_it = elf_info->elf_modules.begin(); modules_it != elf_info->elf_modules.end(); ++modules_it)
			{

				// Collect symbols for preloaded libraries present in link_map, thus have been sucessfully loaded.
				if (contains(preload_libraries_vector, (*modules_it).module_path))
				{
					preload_libraries_in_link_map = true;
					// Get symbol information for preloaded libraries and store it in own symbol_info vector.
					get_symbol_info_32(elf_info->pid, &(*modules_it).elf_mem_hdrs.dyn_info_mem, (*modules_it).base_vaddr, &preload_symbol_info_vector, (*modules_it).module_path, true);
				}

				// Get symbols from non-preloaded libraries in link_map.
				if (!contains(preload_libraries_vector, (*modules_it).module_path))
				{
					// Collect symbol information for NON-preloaded libraries.
					get_symbol_info_32(elf_info->pid, &(*modules_it).elf_mem_hdrs.dyn_info_mem, (*modules_it).base_vaddr, &symbol_info_vector, (*modules_it).module_path, true);
				}
			}

			// If we managed to extract preloaded library symbols
			if (!preload_symbol_info_vector.empty())
			{
				// Compare imported symbols from process executable with preloaded symbols.
				// Matches will indicate a hook is present & working.
				for (auto imports_it = imports_vector.begin(); imports_it != imports_vector.end(); ++imports_it)
				{
					for (auto preloaded_symbols_it = preload_symbol_info_vector.begin(); preloaded_symbols_it != preload_symbol_info_vector.end(); ++preloaded_symbols_it)
					{
						// If there is a match then populate hooked symbol data
						if (strcmp((*imports_it).legit_reloc_func_name.c_str(), (*preloaded_symbols_it).func_name.c_str()) == 0)
						{
							result->preload_hooking_present = true;

							hooked_symbol_info hooked_symbol;
							hooked_symbol.preload_module_path = (*preloaded_symbols_it).module_path;
							hooked_symbol.symbol_name = (*preloaded_symbols_it).func_name;
							hooked_symbol.preload_func_addr = (*preloaded_symbols_it).func_addr;

							for (auto symbols_it = symbol_info_vector.begin(); symbols_it != symbol_info_vector.end(); ++symbols_it)
							{
								// Append path of module(s) symbol was found in.
								if (strcmp((*imports_it).legit_reloc_func_name.c_str(), (*symbols_it).func_name.c_str()) == 0)
								{
									hooked_symbol.original_module_path.append((*symbols_it).module_path);
									hooked_symbol.original_module_path.append(",");
								}
							}

							result->preload_hooked_funcs.push_back(hooked_symbol);
						}
					}
				}
			}
		}
	}
}

inline size_t offset(const char *buf, size_t len, const char *str)
{
	return std::search(buf, buf + len, str, str + strlen(str)) - buf;
}

void check__libc_dlopen_mode_32(pid_t pid, Elf64_Addr base_vaddr, Elf32_Phdr rodata_phdr, std::vector<got_value_32> got_value_vector, library_results *result, ls_flags *my_flags)
{
	// Check to see if we have any got values first.
	if (got_value_vector.empty())
	{
		printf("No GOT values found for pid: %i, skipping check__libc_dlopen_mode_64\n", pid);
		return;
	}

	for (auto it = got_value_vector.begin(); it != got_value_vector.end(); ++it)
	{
		if ((*it).legit_reloc_func_name.compare("__libc_dlopen_mode") == 0)
		{
			// Heuristic 7: GOT address points __libc_dlopen_mode func
			my_flags->ls__libc_dlopen_mode_in_got = true;
			result->__libc_dlopen_mode_present = true;
			result->__libc_dlopen_mode_present_in = "GOT";
		}
	}

	// Read segment containing .rodata section for existence of __libc_dlopen_mode
	char *rodata_mem = (char *)calloc(sizeof(char), rodata_phdr.p_memsz);

	Elf64_Addr rodata_address = (base_vaddr > rodata_phdr.p_vaddr) ? (base_vaddr + rodata_phdr.p_vaddr) : rodata_phdr.p_vaddr;

	// Read whole string table.
	if (process_read(pid, (void *)rodata_mem, (void *)rodata_address, rodata_phdr.p_memsz) == -1)
	{
		printf("Failed to read strtab into memory with process_read(): %s for pid: %i\n", strerror(errno), pid);
		free(rodata_mem);
		return;
	}

	// Search for __libc_dlopen_mode in segment containing rodata section.
	size_t o = offset(rodata_mem, (size_t)rodata_phdr.p_memsz, "__libc_dlopen_mode");
	if (o < rodata_phdr.p_memsz)
	{
		// Heuristic 8: __libc_dlopen_mode string in rodata section. 
		my_flags->ls__libc_dlopen_mode_in_rodata = true;
		result->__libc_dlopen_mode_present = true;

		if (result->__libc_dlopen_mode_present_in.empty())
		{
			result->__libc_dlopen_mode_present_in = "RODATA";
		}
		else
		{
			result->__libc_dlopen_mode_present_in += ":RODATA";
		}
	}

	free(rodata_mem);
}

void cross_ref_mod_lists_32(elf_info_32 elf_info, std::vector<dt_needed_entries> dt_needed_indexes_vector, std::vector<custom_link_map_32> link_maps_vector, std::vector<single_procmap_struct> proc_maps_vector, library_results *result_entry, ls_flags *my_flags)
{
	bool add_entry = false;
	std::string module_name;
	std::vector<std::string> module_proc_maps_names_vector, module_link_map_names_vector, module_dt_needed_names_vector;
	std::vector<uint64_t> module_proc_maps_addresses_vector, module_link_map_addresses_vector;
	std::map<uint64_t, std::string> master_module_names_and_addresses;

	// Extract DT_NEEDED entries
	// Do NOT add to the master list since we can only extract names (which can vary depending on version) and not the base addresses of loaded module to compare with.
	for (auto ij = dt_needed_indexes_vector.begin(); ij != dt_needed_indexes_vector.end(); ++ij)
	{
		module_dt_needed_names_vector.push_back((*ij).module_name);
	}

	// Extract procMaps output - including loaded base addresses
	// Add to master_module_names_and_addresses list
	for (auto it = proc_maps_vector.begin(); it != proc_maps_vector.end(); ++it)
	{
		module_name = (*it).pathname;
		size_t found = module_name.find(".so");

		if (found != std::string::npos)
		{
			if (!contains(module_proc_maps_names_vector, module_name))
			{
				module_proc_maps_names_vector.push_back(module_name);
				module_proc_maps_addresses_vector.push_back((uint64_t)(*it).addr_start);
				master_module_names_and_addresses.emplace((uint64_t)(*it).addr_start, module_name);
			}
		}
	}

	// Extract link_map output - including loaded base addresses
	// Add to master_module_names_and_addresses list
	for (auto ir = link_maps_vector.begin(); ir != link_maps_vector.end(); ++ir)
	{
		size_t lfound = (*ir).library_name.find(".so");
		if (lfound != std::string::npos)
		{
			// ignore vsdo.so
			size_t vsdoFound = (*ir).library_name.find("vdso.so");
			if (vsdoFound != std::string::npos)
			{
				continue;
			}
			module_link_map_names_vector.push_back((*ir).library_name);
			module_link_map_addresses_vector.push_back((uint64_t)(*ir).l_addr);
			master_module_names_and_addresses.emplace((uint64_t)(*ir).l_addr, (*ir).library_name);
		}
	}

	// Do we have irregular hdrs thus a potential DT_NEEDED paching infection
	if (elf_info.elf_mem_hdrs.phdr_irregular_location_mem || elf_info.elf_disk_hdrs.phdr_irregular_location_disk)
	{
		// Heuristic 3: Program headers wrong location. 
		my_flags->ls_phdr_wrong_location = true;
		result_entry->manipulated_program_headers = true;
	}


	// Compare Individual Modules lists with Master List.
	// Using base addresses of modules to compare instead of names (because only partial paths are sometimes given and/or different module version names/numbers used).
	for (auto ik = master_module_names_and_addresses.begin(); ik != master_module_names_and_addresses.end(); ++ik)
	{
		module_cross_references module_cross_references_entry;
		add_entry = false; // Change this back to false!! only change to true to generate false positives.

		module_cross_references_entry.module_path = ik->second;
		module_cross_references_entry.base_addr = ik->first;

		// Does the module have a disk backing.
		if (!exists((ik->second)))
		{
			add_entry = true;
			// Heuristic 4 : Module doesn't have disk backing. Checks for every module.
			my_flags->ls_mod_missing_disk_backing = true;
			module_cross_references_entry.disk_backed = false;
		}

		if (!contains(module_proc_maps_addresses_vector, (ik->first)))
		{
			add_entry = true;
			// Heuristic 5: Module doesn't exist in /proc/<pid>/maps. Checks for every module.
			my_flags->ls_module_not_in_procmaps = true;
			module_cross_references_entry.in_proc_maps_list = false;
		}

		if (!contains(module_link_map_addresses_vector, (ik->first)))
		{
			add_entry = true;
			// False positives will be produced - As link_maps can't be found in shell scripts running as processes & docker containers.
			// Heuristic 6: Module doesn't exist in link_map structure. Checks for every module.
			my_flags->ls_module_not_in_linkmap = true;
			module_cross_references_entry.in_link_maps_list = false;
		}

		if (add_entry)
		{
			// We are only intrested in DT_NEEDED names if a heuristic fires.
			for (auto il = module_dt_needed_names_vector.begin(); il != module_dt_needed_names_vector.end(); ++il)
			{
				size_t lfound = ik->second.find((*il));
				if (lfound != std::string::npos)
				{
					module_cross_references_entry.in_dt_needed_list = true;
				}
			}

			result_entry->module_cross_references_vector.push_back(module_cross_references_entry);
		}
	}
}

void collect_library_results_32(elf_info_32 elf_info, std::vector<library_results> *library_results_vector, config my_config)
{

	// Is pid still alive, this is vital.

	/* Validate data first, if false then quit
    if (!validate_data_64(elf_info_64))
    {
        printf("Validate\n");
        return;
    }
    */

	ls_flags my_flags;

	// vector<symbol_info> ld_preload_symbol_info_vector, symbol_info_vector;
	library_results result;
	bool add_result = false;
	// bool ld_preload_in_link_map = false;

	// Populate our results vector with fields already collected by elf_info.cpp
	result.proc_start_time = elf_info.proc_start_time;
	result.pid = elf_info.pid;
	result.ppid = elf_info.ppid;
	result.hostname = elf_info.hostname;
	result.base_address = elf_info.base_vaddr;
	result.process_path = elf_info.process_path;
	result.cmdline = elf_info.cmdline;
	result.disk_backed = elf_info.disk_backed;
	result.debug_section_present = elf_info.elf_mem_hdrs.dyn_info_mem.dt_debug_present;
	result.dt_null_present = elf_info.elf_mem_hdrs.dyn_info_mem.dt_null_present;
	result.dynamic_segment_present = elf_info.elf_mem_hdrs.dynamic_segment_present;
	result.dynstr_manipulated = elf_info.elf_mem_hdrs.dyn_info_mem.dt_strtab_manipulated;
	result.dt_needed_wrong_order = elf_info.elf_mem_hdrs.dyn_info_mem.dt_needed_wrong_order;
	result.dt_needed_indexes_vector = elf_info.elf_mem_hdrs.dyn_info_mem.dt_needed_indexes_vector;

	// Populate our stack variables.
	result.ld_config_present = elf_info.stack_variables.ld_config_present;
	result.ld_config = elf_info.stack_variables.ld_config;
	result.ld_path_present = elf_info.stack_variables.ld_path_present;
	result.ld_path = elf_info.stack_variables.ld_path;
	result.ld_preload_present = elf_info.stack_variables.ld_preload_present;
	result.ld_preload = elf_info.stack_variables.ld_preload;

	// Check for anonymous memory mappings.
	get_anonymous_mappings(elf_info.pid, &elf_info.proc_maps_vector, &result.anonymous_memory_mappings_vector, &my_flags);

	// Check for module enumeration mismatches.
	cross_ref_mod_lists_32(elf_info, elf_info.elf_mem_hdrs.dyn_info_mem.dt_needed_indexes_vector, elf_info.elf_mem_hdrs.dyn_info_mem.link_map, elf_info.proc_maps_vector, &result, &my_flags);

	// We need the processe's got values to determine if it is importing '__libc_dlopen_mode' which is an attacker method of loading a shared object.
	get_jump_entry_relocations_32(elf_info.pid, &elf_info.elf_mem_hdrs.dyn_info_mem, elf_info.base_vaddr, &elf_info.elf_mem_hdrs.dyn_info_mem.got_value_vector);

	// Check for hooking of functions using LD_PRELOAD variables.
	check_preload_hooking_32(&elf_info, &result, elf_info.elf_mem_hdrs.dyn_info_mem.got_value_vector);

	// Check for '__libc_dlopen_mode' as a imported function in the GOT.
	check__libc_dlopen_mode_32(elf_info.pid, elf_info.base_vaddr, elf_info.elf_mem_hdrs.rodata_pHdr_mem, elf_info.elf_mem_hdrs.dyn_info_mem.got_value_vector, &result, &my_flags);

	// Set heuristic flags.
	set_remaining_flags(result, &my_flags);

	// Check against heuristic config
	check_library_config_settings(my_config, my_flags, &add_result);

	if (add_result)
	{
		// pushback result into results vector.
		library_results_vector->push_back(result);
	}
}

void *start_library_thread_32(void *threadarg)
{

	library_thread_data_32 *my_data;
	my_data = (library_thread_data_32 *)threadarg;

	// Cycle through all elf_info_64_vectors given to a single thread.
	for (auto it = my_data->elf_info_32_vector->begin(); it != my_data->elf_info_32_vector->end(); ++it)
	{
		// Collect our results.
		collect_library_results_32((*it), my_data->results_vector, my_data->my_config);
	}

	pthread_exit(NULL);
}

void library_scanner_main_32(elf_info_32_group *elf_info_32_pots, config my_config)
{
	std::vector<library_results> results_vector[THREAD_COUNT];
	pthread_t threads[THREAD_COUNT];
	library_thread_data_32 td[THREAD_COUNT]; // Thread data needs be changed for specific to scanner results.
	pthread_attr_t attr;
	void *status;
	int rc;
	timespec start_time, end_time;
	time_t elapsed_seconds;
	long elapsed_nanoseconds;
	std::string output_filename = elf_info_32_pots->elf_info_32_pots[0][0].hostname + "_library_scanner_output_32.json";

	printf("Starting library scanner x86\n");
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
		td[i].my_config = my_config;
		td[i].elf_info_32_vector = &elf_info_32_pots->elf_info_32_pots[i];
		td[i].results_vector = &results_vector[i];
		td[i].thread_id = i;

		// td[i].results_vector = results_vector; - TODO. This will have to be some kind of results template, since all scanners will have different results_vector type e.g. library_results_vector.

		// Create thread sending it to analyze_group function.
		rc = pthread_create(&threads[i], NULL, start_library_thread_32, (void *)&td[i]);
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

	// Print results, use flag to select which print statement to use.
	library_results_writer(output_filename.c_str(), &results_vector[0]);

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

	printf("Finished library scanner x86\n");
	printf("Library Scanner x86 runtime: %lu.%lus\n", elapsed_seconds, elapsed_nanoseconds);
}
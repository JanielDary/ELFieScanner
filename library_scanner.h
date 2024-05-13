#ifndef LIBRARY_SCANNER_H_
#define LIBRARY_SCANNER_H_

#include "elf_info.h" // We have to include this, unless we want to redifine all the custom elf_info related structs here.

#include <string>
#include <string.h>
#include <elf.h>
#include <fstream>
#include <regex>
#include <time.h>

#define MAX_SIZE_ANONYMOUS_MAPPING 10485760 // 10MB.
#define LIBRARY_SCANNER 0x00000002

struct ls_flags
{

	// Each flag is prepended with 'ls' referring to 'library scanner'. This is to avoid confusion when one heuristics applies to multiple scanners.

	// Heuristic 1 : ELF header found in anonymous memory mapping
	bool ls_elf_in_anonymous_mapping = false;
	// Heuristic 2 : Executable anonymous memory mapping
	bool ls_executable_anonymous_mapping = false;
	// Heuristic 3: Program headers wrong location. 
	bool ls_phdr_wrong_location = false;
	// Heuristic 4 : Module doesn't have disk backing. Checks for every module.
	bool ls_mod_missing_disk_backing = false;
	// Heuristic 5: Module doesn't exist in /proc/<pid>/maps. Checks for every module.
	bool ls_module_not_in_procmaps = false;
	// Heuristic 6: Module doesn't exist in link_map structure. Checks for every module.
	bool ls_module_not_in_linkmap = false;
	// Heuristic 7: GOT address points __libc_dlopen_mode func.
	bool ls__libc_dlopen_mode_in_got = false;
	// Heuristic 8: __libc_dlopen_mode string in rodata section.
	bool ls__libc_dlopen_mode_in_rodata = false;
	// Heuristic 9 : DT_NULL missing from dynamic section.
	bool ls_dtnull_missing = false;
	// Heuristic 10: DT_DEBUG missing from dynamic section
	bool ls_dtdebug_missing = false;
	// Heuristic 11: DT_NEEDED in non-sequential (incorrect) order in dynamic section
	bool ls_dtneeded_incorrect_order = false;
	// Heuristic 12: Dynamic string table manually manipulated
	bool ls_dynstr_manipulated = false;
	// Heuristic 13: LD_PRELOAD populated
	bool ls_ldpreload_set = false;
	// Heuristic 14: LD_PRELOAD hooking present
	bool ls_ldpreload_hooking = false;
	// Heuristic 15: LD_CONFIG populated
	bool ls_ldconfig_set = false;
	// Heuristic 16: LD_PATH manipulated
	bool ls_ldpath_set = false;
	// Heuristic 17: Dynamic segment missing
	bool ls_dynamic_segment_missing = false;
};

struct symbol_info
{
	std::string module_path;
	Elf64_Addr func_addr;
	std::string func_name;
};

struct hooked_symbol_info
{
	std::string original_module_path;
	std::string preload_module_path;
	Elf64_Addr preload_func_addr;
	std::string symbol_name;
};

struct partial_hash_table
{
	uint32_t nbucket; //
	uint32_t nchain;  // Equals number of Symbol table entries! The Symbol Table to hold the STN_UNDEF symbol at 0 index. So effectively a chain breaks when current index is 0.
};

struct partial_gnu_hash_table
{
	uint32_t nbuckets;
	uint32_t symoffset;
	uint32_t bloom_size;
	uint32_t bloom_shift;
};

struct anonymous_mappings
{
	uint64_t start_addr;
	uint64_t end_addr;
	bool elf_magic_present = false;
	uint64_t elf_magic_index;
	short is_r;
	short is_w;
	short is_x;
	short is_p;
};

/*
struct dt_needed_entries
{
	uint32_t index_into_dt_strtab; // The DT_STRTAB (Dynamic string table) offset of a null-terminated string, giving the name of a needed dependency. String table is small hence uint32 is big enough for both 32 & 64-bit.
	std::string module_name;	   // Module name from DT_STRTAB (Dynamic string table)
	int dt_needed_index;		   // Index the entry appears in dynamic section
	bool name_in_dynstr = true;	   // Does module name appear within original confines of DT_STRTAB (Dynamic string table)
}; */

struct module_cross_references
{
	std::string module_path;
	bool in_dt_needed_list = false;
	bool in_link_maps_list = true;
	bool in_proc_maps_list = true;
	bool disk_backed = true;
	Elf64_Addr base_addr; // NOTE: DT_Needed entries don't only provides names hence this can only be populated by LinkMap and ProcMaps metadata.
};

struct library_results
{
	time_t proc_start_time;
	pid_t pid;
	pid_t ppid;
	std::string hostname;
	std::string process_path;
	uint64_t base_address;
	std::string cmdline;

	bool disk_backed = false;

	bool dynamic_segment_present = true;
	bool debug_section_present;
	bool manipulated_program_headers = false;
	bool dynstr_manipulated = false;

	bool dt_null_present = true;
	bool dt_needed_wrong_order = false;
	std::vector<dt_needed_entries> dt_needed_indexes_vector;

	bool ld_preload_present = false;
	std::string ld_preload;
	std::vector<std::string> preloaded_libraries; 
	bool preload_hooking_present = false;
	std::vector<hooked_symbol_info> preload_hooked_funcs;
	// vector<string, string> hooked_funcs;

	bool ld_config_present = false;
	std::string ld_config;

	bool ld_path_present = false;
	std::string ld_path;

	std::vector<anonymous_mappings> anonymous_memory_mappings_vector;

	bool __libc_dlopen_mode_present = false;
	std::string __libc_dlopen_mode_present_in;
	// Elf64_Addr got_libc_dlopen_mode_addr = 0;

	std::vector<module_cross_references> module_cross_references_vector;
};

struct library_thread_data_64
{
	config my_config;
	int thread_id;
	std::vector<elf_info_64> *elf_info_64_vector;
	std::vector<library_results> *results_vector; // This is an overall vector for all scanners.
};

struct library_thread_data_32
{
	config my_config;
	int thread_id;
	std::vector<elf_info_32> *elf_info_32_vector;
	std::vector<library_results> *results_vector; // This is an overall vector for all scanners.
};

// Generic funcs 
void library_results_writer(const char *name, std::vector<library_results> *results_vector);
uint32_t parse_gnu_hash_table(pid_t pid, Elf64_Addr base_vaddr, Elf64_Addr gnu_hash_table_addr);
bool get_anonymous_mappings(pid_t pid, std::vector<single_procmap_struct> *proc_maps_vector, std::vector<anonymous_mappings> *anonymous_mappings_vector, ls_flags *my_flags);
void get_preload_libraries(std::string ld_preload, std::vector<std::string> *preload_libraries_vector);
void set_remaining_flags(library_results result, ls_flags *my_flags);
void check_library_config_settings(config my_config, ls_flags my_flags, bool *add_result);

// 64-bit funcs
void get_symbol_info_64(pid_t pid, dynamic_info64 *dynamic_info, Elf64_Addr base_vaddr, std::vector<symbol_info> *mod_info, std::string module_name, bool extract_only_symbols_with_data);
void get_jump_entry_relocations64(pid_t pid, dynamic_info64 *dynamic_info, Elf64_Addr base_vaddr, std::vector<got_value_64> *got_values_vector);
// void check_ld_preload_hooking_64(elf_info_64 *elf_info, library_results *result, bool *add_result);
void check_preload_hooking_64(elf_info_64 *elf_info, library_results *result, std::vector<got_value_64> imports_vector);
// void check__libc_dlopen_mode_64(pid_t pid, std::vector<got_value_64> got_value_vector, library_results *result, bool *add_result);
void check__libc_dlopen_mode_64(pid_t pid, Elf64_Addr base_vaddr, Elf64_Phdr rodata_phdr, std::vector<got_value_64> got_value_vector, library_results *result, ls_flags *my_flags);

void cross_ref_mod_lists_64(elf_info_64 elf_info, std::vector<dt_needed_entries> dt_needed_indexes_vector, std::vector<custom_link_map_64> link_map_vector, std::vector<single_procmap_struct> proc_maps_vector, library_results *result_entry, ls_flags *my_flags);
void collect_library_results_64(elf_info_64 elf_info, std::vector<library_results> *library_results_vector, config my_config);
void *start_library_thread_64(void *threadarg);
void library_scanner_main_64(elf_info_64_group *elf_info_64_vector, config my_config);

// 32-bit funcs
void get_symbol_info_32(pid_t pid, dynamic_info32 *dynamic_info, Elf64_Addr base_vaddr, std::vector<symbol_info> *symbol_info_vector, std::string module_name, bool extract_only_symbols_with_data);
void get_jump_entry_relocations_32(pid_t pid, dynamic_info32 *dynamic_info, Elf64_Addr base_vaddr, std::vector<got_value_32> *got_values_vector);
// void check_ld_preload_hooking_32(elf_info_32 *elf_info, library_results *result, bool *add_result);
void check_preload_hooking_32(elf_info_32 *elf_info, library_results *result, std::vector<got_value_32> imports_vector);
// void check__libc_dlopen_mode_32(pid_t pid, std::vector<got_value_32> got_value_vector, library_results *result, bool *add_result);
void check__libc_dlopen_mode_32(pid_t pid, Elf64_Addr base_vaddr, Elf32_Phdr rodata_phdr, std::vector<got_value_32> got_value_vector, library_results *result, ls_flags *my_flags);
void cross_ref_mod_lists_32(elf_info_32 elf_info, std::vector<dt_needed_entries> dt_needed_indexes_vector, std::vector<custom_link_map_32> link_maps_vector, std::vector<single_procmap_struct> proc_maps_vector, library_results *result_entry, ls_flags *my_flags);
void collect_library_results_32(elf_info_32 elf_info, std::vector<library_results> *library_results_vector, config my_config);
void *start_library_thread_32(void *threadarg);
void library_scanner_main_32(elf_info_32_group *elf_info_32_pots, config my_config);

#endif
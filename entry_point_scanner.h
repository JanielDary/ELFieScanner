#ifndef ENTRY_POINT_SCANNER_H_
#define ENTRY_POINT_SCANNER_H_

#include "elf_info.h" // We have to include this, unless we want to redifine all the custom elf_info related structs here.

#include <fuzzy.h>
#include <string>
#include <string.h>
#include <vector>
#include <elf.h>
#include <fstream>
#include <time.h>

#define ENTRY_POINT_SCANNER 0x00000001

struct es_flags
{
    // Each flag is prepended with 'es' referring to 'entrypoint scanner'. This is to avoid confusion when one heuristics applies to multiple scanners.

    bool es_section_hdr_missing = false;            // Heuristic 1 : Section headers can been stripped from a binary (this is suspicious but not necessarily malicious). Stripping the section headers makes reverse engineering of the binary more difficult. However it could be done make the binary smaller.
                                                 // e_shoff This member holds the section header table's file offset in bytes. If the file has no section header table, this member holds zero.
    bool es_phdr_wrong_location = false;            // Heuristic 2: Check to see if if the program headers start in the expected place (immediately after the ELF32_Ehdr/ELF64_Ehdr) e.g. 64 bytes offset for 64-bit, or 52 bytes offset for 32-bit.
    bool es_proc_missing_disk_backing = false;      // Heuristic 3: Check the process is not backed by disk executable. More of an anomaly rather than a detection.
    bool es_proc_text_segment_missing_disk = false; // Heuristic 4: Check to see if the .text segment is present on disk. This should always be present unless the binary is still packed/obfuscated in memory.
    bool es_proc_text_segment_missing_mem = false;  // Heuristic 5: Is the .text segment is present in memory. This should always be present unless the disk backed binary is packed/obfuscated.
    bool es_proc_entry_points_not_in_text = false;  // Heuristic 6: Check to see if the e_entry field does NOT point within the .text segment. This should always be the case apart from special cases such as ‘VBoxService’.
    bool es_proc_entry_points_not_matching = false; // Heuristic 7: Check to see if the e_entry values for process & disk binary match.
    int es_proc_entry_fuzzy_score = 100;            // Heuristic 8: Check the e_entry for the libc linked process matches the expected initialization code for ‘libc_start_main’. Highly suspicious unless this is for an interpreter process e.g. ‘/usr/bin/python’ OR container processes ‘/usr/sbin/VBoxService’

    bool es_proc_init_fini_not_in_text = false; // Heuristic 9:
                                             // process init/fini sections that don't appear in .text segment
                                             // process preinit/init/fini array functions that don't point within the .text segment.

    bool es_proc_init_not_at_text_start = false; // Heuristic 10: For processes it is expected the .init code block should begin at the start of the .text segment. NOTE: this is not expected for modules.

    bool es_mod_missing_disk_backing = false;      // Heuristic 11: Check to see if module is backed by disk executable. More of an anomaly rather than a detection. Check against every module.
    bool es_mod_entry_points_not_in_text = false;  // Heuristic 12: Check the e_entry field points within .text segment of the module. This should always be the case for modules. Check against every module
    bool es_mod_entry_points_not_matching = false; // Heuristic 13: Check to see the e_entry values for module and disk match. Check against every module.

    bool es_mod_init_fini_not_in_text = false; // Heuristic 14:
                                            // module init/fini sections that don't appear in .text segment
                                            // module preinit/init/fini array functions that don't point within the .text segment. 
                                            // Checks against every module. 
};

struct init_fini_comparisions
{
    bool init_at_text_start = true;
    bool init_in_text = true;
    bool fini_in_text = true;
    bool init_array_in_text = true;
    int number_of_init_array_funcs = 0;
    bool fini_array_in_text = true;
    int number_of_fini_array_funcs = 0;
    bool preinit_array_in_text = true;
    int number_of_preinit_array_funcs = 0;
};

// Refactor to module_entry_point_results
struct module_entry
{
    std::string module_path;
    bool disk_backed = false;
    bool entry_points_match = false;
    bool entry_point_in_text = false;
    struct init_fini_comparisions mod_init_fini;
};

struct entry_point_results
{
    time_t proc_start_time;
    pid_t pid;
    pid_t ppid;
    std::string hostname;
    std::string process_path;
    uint64_t base_address;
    std::string cmdline;

    bool disk_backed = false;

    bool libc_present = false;
    bool text_segment_present_mem = false;
    bool text_segment_present_disk = false;
    bool dynamic_segment_present = false;
    int entry_fuzzy_score = -1;
    bool entry_points_match = false;
    bool entry_point_in_text = false; // add this for disk & mem.

    struct init_fini_comparisions proc_init_fini;
    std::vector<module_entry> module_results;

    bool manipulated_program_headers = false;
    int phdr_off = -1; // -1 indicates no result stored
    int shdr_off = -1; // -1 indicates no results stored
};

struct entry_point_thread_data_64
{
    config my_config;
    int thread_id;
    std::vector<elf_info_64> *elf_info_64_vector;
    std::vector<entry_point_results> *results_vector; // This is an overall vector for all scanners.
};

struct entry_point_thread_data_32
{
    config my_config;
    int thread_id;
    std::vector<elf_info_32> *elf_info_32_vector;
    std::vector<entry_point_results> *results_vector; // This is an overall vector for all scanners.
};

// Generic funcs
void to_json_entry_point(json &j, const entry_point_results &r);
void entry_point_results_writer(const char *name, std::vector<entry_point_results> *results_vector);
bool sits_within(Elf64_Addr address, Elf64_Addr low_address, Elf64_Addr high_address);
bool filter_modules(module_entry module_result, init_fini_comparisions mod_init_fini, std::string module_path);
void set_flags(entry_point_results *result, es_flags *my_flags);
void check_entry_config_settings(config my_config, es_flags my_flags, bool *add_result);

// 64-bit funcs
void compare_entry_64(Elf64_Addr base_vaddr, Elf64_Ehdr ehdr_mem, Elf64_Phdr text_pHdr_mem, Elf64_Ehdr ehdr_disk, bool *entry_points_match, bool *entry_point_in_text);
void compare_init_fini_64(pid_t pid, Elf64_Addr base_vaddr, dynamic_info64 dynamic_info, Elf64_Phdr text_pHdr_mem, init_fini_comparisions *mod_init_fini);
void collect_entry_point_results_64(elf_info_64 elf_info, std::vector<entry_point_results> *entry_point_results_vector, config my_config);
void *start_entry_point_thread_64(void *threadarg);
void entry_point_scanner_main_64(elf_info_64_group *elf_info_64_vector, config my_config);

// 32-bit funcs
int libc_entry_fuzzy_score_32(pid_t pid, Elf64_Addr entry_address, Elf64_Addr base_vaddr);
void compare_entry_32(Elf64_Addr base_vaddr, Elf32_Ehdr ehdr_mem, Elf32_Phdr text_pHdr_mem, Elf32_Ehdr ehdr_disk, bool *entry_points_match, bool *entry_point_in_text);
void compare_init_fini_32(pid_t pid, Elf32_Addr base_vaddr, dynamic_info32 dynamic_info, Elf32_Phdr text_pHdr_mem, init_fini_comparisions *init_fini_result);
void collect_entry_point_results_32(elf_info_32 elf_info, std::vector<entry_point_results> *entry_point_results_vector, config my_config);
void *start_entry_point_thread_32(void *threadarg);
void entry_point_scanner_main_32(elf_info_32_group *elf_info_32_pots, config my_config);

#endif
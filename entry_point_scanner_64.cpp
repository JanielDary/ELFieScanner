
#include "entry_point_scanner.h"

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(init_fini_comparisions,
                                   init_at_text_start,
                                   init_in_text,
                                   fini_in_text,
                                   init_array_in_text,
                                   number_of_init_array_funcs,
                                   fini_array_in_text,
                                   number_of_fini_array_funcs,
                                   preinit_array_in_text,
                                   number_of_preinit_array_funcs)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(module_entry,
                                   module_path,
                                   disk_backed,
                                   entry_points_match,
                                   entry_point_in_text,
                                   mod_init_fini)

void to_json_entry_point(json &j, const entry_point_results &r)
{
    j = json{
        {"timestamp", r.proc_start_time},
        {"pid", r.pid},
        {"ppid", r.ppid},
        {"hostname", r.hostname},
        {"proc_path", r.process_path},
        {"cmdl", r.cmdline},
        {"disk_backed", r.disk_backed},
        {"dynamic_segment_present", r.dynamic_segment_present},
        {"text_segment_present_disk", r.text_segment_present_disk},
        {"text_segment_present_mem", r.text_segment_present_mem},
        {"entry_points_match", r.entry_points_match},
        {"entry_point_in_text", r.entry_point_in_text},
        {"libc_present", r.libc_present},
        {"entry_score", r.entry_fuzzy_score},
        {"proc_init_fini", r.proc_init_fini},
        {"module_results", r.module_results},
        {"program_hdr_offset", r.phdr_off},
        {"section_hdr_offset", r.shdr_off},
        {"manipulated_program_headers", r.manipulated_program_headers}};
}

void entry_point_results_writer(const char *name, std::vector<entry_point_results> *results_vector)
{
    // Prints a NDJSON file.

    std::ofstream outputFile(name, std::ios::out | std::ios::trunc);

    if (outputFile.is_open())
    {
        for (auto it = results_vector->begin(); it != results_vector->end(); ++it)
        {
            json j;
            to_json_entry_point(j, (*it));

            outputFile << j;
            outputFile << std::endl;
        }

        outputFile.close();
    }
    else
    {
        printf("Unable to open File, in resultsWriter Function\n");
        return;
    }
}

bool sits_within(Elf64_Addr address, Elf64_Addr low_address, Elf64_Addr high_address)
{
    if ((address >= low_address) && (address < high_address))
    {
        return true;
    }
    else
    {
        return false;
    }
}

int libc_entry_fuzzy_score_64(pid_t pid, Elf64_Addr entry_address, Elf64_Addr base_vaddr)
{
    int fuzzy_score;
    char fuzzy_hash[FUZZY_MAX_RESULT];
    const char *expected_fuzzy_hash;
    unsigned char initialization_code[42];

    // Make sure entry point is an absolute virtual address.
    entry_address = (base_vaddr > entry_address) ? (base_vaddr + entry_address) : entry_address;

    // Read size of initialization code from memory e_entry
    if (process_read(pid, initialization_code, (const void *)entry_address, 42))
    {
        printf("Failed to initialization code with process_read() in function 'libc_entry_fuzzy_score_64': %s for pid: %i\n", strerror(errno), pid);
        return false;
    }


    // New case
    if (initialization_code[22] == 0x31 && initialization_code[23] == 0xc9)
    {
        expected_fuzzy_hash = "3:bNCY4X:bNClX";


        // Generate fuzzy hash
        fuzzy_hash_buf((const unsigned char *)initialization_code, 24, fuzzy_hash);

        // Compare fuzzy has against hard coded fuzzy hash score.
        fuzzy_score = fuzzy_compare(fuzzy_hash, expected_fuzzy_hash);

        if(fuzzy_score != 100)
        {
            printf("NewFuzzy Hash:%s\n", fuzzy_hash);
        }

        return fuzzy_score;
    }



    // Check to see if we have libc@plt or libc@GLIBC & then NUll out bytes responsible for %rip relative addressing.
    if (initialization_code[0] == 0x31 && initialization_code[1] == 0xed && initialization_code[2] == 0x49 && initialization_code[3] == 0x89)
    {
        // Init code refers to libc@plt or main.
        for (int k = 15; k < 42; k++)
        {

            if (k != 22 || k != 29)
            {

                initialization_code[k] = 0x00;
            }
        }

        expected_fuzzy_hash = "3:Rsq4:s";
    }
    else
    {

        initialization_code[22] = 0x00;
        initialization_code[23] = 0x00;
        initialization_code[24] = 0x00;
        initialization_code[25] = 0x00;

        initialization_code[29] = 0x00;
        initialization_code[30] = 0x00;
        initialization_code[31] = 0x00;
        initialization_code[32] = 0x00;

        initialization_code[36] = 0x00;
        initialization_code[37] = 0x00;
        initialization_code[38] = 0x00;
        initialization_code[39] = 0x00;

        expected_fuzzy_hash = "3:bNCY4VXtoatV:bNClltoeV";
    }


    // Generate fuzzy hash
    fuzzy_hash_buf((const unsigned char *)initialization_code, 42, fuzzy_hash);

    /*
    printf("PID: %i	EntryAddress: 0X%lx	Fuzz:%s\n", pid, entry_address, fuzzy_hash);
    printf("InitCode:	");

    for (int i = 0; i < 42; i++)
    {
        printf("%02x ", initialization_code[i]);
    }
    printf("\n");
    */

    // Compare fuzzy has against hard coded fuzzy hash score.
    fuzzy_score = fuzzy_compare(fuzzy_hash, expected_fuzzy_hash);

    return fuzzy_score;
}

void compare_entry_64(Elf64_Addr base_vaddr, Elf64_Ehdr ehdr_mem, Elf64_Phdr text_pHdr_mem, Elf64_Ehdr ehdr_disk, bool *entry_points_match, bool *entry_point_in_text)
{

    // Do Disk and Memory entry points match.
    if (ehdr_mem.e_entry == ehdr_disk.e_entry)
    {
        *entry_points_match = true;
    }

    // Correct relative addresses to base addresses if necessary
    text_pHdr_mem.p_vaddr = (base_vaddr < text_pHdr_mem.p_vaddr) ? text_pHdr_mem.p_vaddr : (base_vaddr + text_pHdr_mem.p_vaddr);
    ehdr_mem.e_entry = (base_vaddr < ehdr_mem.e_entry) ? ehdr_mem.e_entry : (base_vaddr + ehdr_mem.e_entry);

    // Does entry point sit within the text segment i.e. RX segment.
    if (sits_within(ehdr_mem.e_entry, text_pHdr_mem.p_vaddr, (text_pHdr_mem.p_vaddr + text_pHdr_mem.p_memsz)))
    {
        *entry_point_in_text = true;
    }
}

void compare_init_fini_64(pid_t pid, Elf64_Addr base_vaddr, dynamic_info64 dynamic_info, Elf64_Phdr text_pHdr_mem, init_fini_comparisions *init_fini_result)
{
    /* Explanation of execution order with regards to .init, .init_array, .fini, .fini_array & preinit_array sections.
    https://docs.oracle.com/cd/E19683-01/817-3677/6mj8mbtbi/index.html
    */

    // Update addresses with absolute addresses if currently a relative address. So we can read data from process with ptrace read.
    text_pHdr_mem.p_vaddr = (text_pHdr_mem.p_vaddr > base_vaddr) ? text_pHdr_mem.p_vaddr : base_vaddr + text_pHdr_mem.p_vaddr;
    dynamic_info.dt_init = (dynamic_info.dt_init > base_vaddr) ? dynamic_info.dt_init : base_vaddr + dynamic_info.dt_init;
    dynamic_info.dt_fini = (dynamic_info.dt_fini > base_vaddr) ? dynamic_info.dt_fini : base_vaddr + dynamic_info.dt_fini;
    dynamic_info.dt_init_array = (dynamic_info.dt_init_array > base_vaddr) ? dynamic_info.dt_init_array : base_vaddr + dynamic_info.dt_init_array;
    dynamic_info.dt_fini_array = (dynamic_info.dt_fini_array > base_vaddr) ? dynamic_info.dt_fini_array : base_vaddr + dynamic_info.dt_fini_array;
    dynamic_info.dt_preinit_array = (dynamic_info.dt_preinit_array > base_vaddr) ? dynamic_info.dt_preinit_array : base_vaddr + dynamic_info.dt_preinit_array;

    uint64_t *dt_preinit_array_mem, *dt_init_array_mem, *dt_fini_array_mem;

    // Functions in the initArray, preinitArray and finiArray are executed by the runtime linker.
    // Whereas the the .init and .fini functions are executed by the application itself.
    // As such these are a more likely candidate to be abused by attackers.

    // Does dt_init start at start of text segment?
    if (dynamic_info.dt_init_present)
    {
        // Does dt_int point the the start of the .text section?
        if (dynamic_info.dt_init != text_pHdr_mem.p_vaddr)
        {
            // printf("init doesn't point to the start of the text section\n");
            init_fini_result->init_at_text_start = false;
        }

        if (!sits_within(dynamic_info.dt_init, text_pHdr_mem.p_vaddr, (text_pHdr_mem.p_vaddr + text_pHdr_mem.p_memsz)))
            init_fini_result->init_in_text = false;
    }

    // Does dt_fini sit within text segment.
    if (dynamic_info.dt_fini_present)
    {
        if (!sits_within(dynamic_info.dt_fini, text_pHdr_mem.p_vaddr, (text_pHdr_mem.p_vaddr + text_pHdr_mem.p_memsz)))
            init_fini_result->fini_in_text = false;
    }

    // Do preinit, init & fini arrays function sit within text segment.
    if (dynamic_info.dt_preinit_array_present && dynamic_info.dt_preinit_arraysz_present)
    {
        dt_preinit_array_mem = (uint64_t *)alloca(dynamic_info.dt_preinit_arraysz);

        if (process_read(pid, dt_preinit_array_mem, (void *)dynamic_info.dt_preinit_array, dynamic_info.dt_preinit_arraysz) == -1)
        {
            printf("Failed to read preinitArray with process_read() in function 'compare_init_fini_64': %s\n", strerror(errno));
            return;
        }

        // Iterate through preinitArray addresses to make sure they point within the text section.
        Elf64_Addr function_pointer;
        int number_of_function_pointers = dynamic_info.dt_preinit_array / sizeof(Elf64_Addr);

        init_fini_result->number_of_preinit_array_funcs = number_of_function_pointers;

        for (int i = 0; i < number_of_function_pointers; i++)
        {
            function_pointer = dt_preinit_array_mem[i];

            // Does function pointer to to an address within the text segment?
            if (!sits_within(function_pointer, text_pHdr_mem.p_vaddr, (text_pHdr_mem.p_vaddr + text_pHdr_mem.p_memsz)))
                init_fini_result->preinit_array_in_text = false;
        }
    }

    if (dynamic_info.dt_init_array_present && dynamic_info.dt_init_arraysz_present)
    {
        dt_init_array_mem = (uint64_t *)alloca(dynamic_info.dt_init_arraysz);

        if (process_read(pid, dt_init_array_mem, (void *)dynamic_info.dt_init_array, dynamic_info.dt_init_arraysz) == -1)
        {
            printf("Failed to read initArray with process_read() in function 'compare_init_fini_64': %s\n", strerror(errno));
            return;
        }

        Elf64_Addr function_pointer;
        // Iterate through initArray addresses to make sure they point within the text section.
        int number_of_function_pointers = dynamic_info.dt_init_arraysz / sizeof(Elf64_Addr);

        init_fini_result->number_of_init_array_funcs = number_of_function_pointers;

        for (int j = 0; j < number_of_function_pointers; j++)
        {
            function_pointer = dt_init_array_mem[j];

            if (!sits_within(function_pointer, text_pHdr_mem.p_vaddr, (text_pHdr_mem.p_vaddr + text_pHdr_mem.p_memsz)))
                init_fini_result->init_array_in_text = false;
        }
    }

    if (dynamic_info.dt_fini_array_present && dynamic_info.dt_fini_arraysz_present)
    {
        dt_fini_array_mem = (uint64_t *)alloca(dynamic_info.dt_fini_arraysz);

        if (process_read(pid, dt_fini_array_mem, (void *)dynamic_info.dt_fini_array, dynamic_info.dt_fini_arraysz) == -1)
        {
            printf("Failed to read finiArray with process_read() in function 'compare_init_fini_64': %s\n", strerror(errno));
            return;
        }

        Elf64_Addr function_pointer;
        int number_of_function_pointers = dynamic_info.dt_fini_arraysz / sizeof(Elf64_Addr);

        init_fini_result->number_of_fini_array_funcs = number_of_function_pointers;

        for (int k = 0; k < number_of_function_pointers; k++)
        {
            function_pointer = dt_fini_array_mem[k];

            if (!sits_within(function_pointer, text_pHdr_mem.p_vaddr, (text_pHdr_mem.p_vaddr + text_pHdr_mem.p_memsz)))
                init_fini_result->fini_array_in_text = false;
        }
    }
}

bool filter_modules(module_entry module_result, init_fini_comparisions mod_init_fini, std::string module_path)
{

    bool add_result = false;
    bool libc_module = false;

    // If entry points don't match or point within the .text segment.
    if ((!module_result.entry_point_in_text) || (!module_result.entry_points_match))
    {
        add_result = true;
    }

    // Same again for pre-init, init & fini functions.
    if ((!mod_init_fini.init_in_text) || (!mod_init_fini.fini_in_text) ||
        (!mod_init_fini.init_array_in_text) || (!mod_init_fini.fini_array_in_text) ||
        (!mod_init_fini.preinit_array_in_text))
    {

        add_result = true;
    }

    // Init function doesn't start at the begging of libc.so's text segment
    // Hence this is filtering it out to avoid lots of false positives.
    if (std::string::npos != module_path.find("libc.so"))
    {
        libc_module = true;
    }

    // Removing this heuristic entirely will eliminate allmost module false +ves
    if ((!mod_init_fini.init_at_text_start) && (!libc_module))
        add_result = true;

    return add_result;
}

void set_flags(entry_point_results *result, es_flags *my_flags)
{
    if (result->shdr_off == 0)
        my_flags->es_section_hdr_missing = true; // Heuristic 1 : Section headers can been stripped from a binary (this is suspicious but not necessarily malicious).

    if (result->manipulated_program_headers)
        my_flags->es_phdr_wrong_location = true; // Heuristic 2: Check to see if if the program headers start in the expected place (immediately after the ELF32_Ehdr/ELF64_Ehdr) e.g. 64 bytes offset for 64-bit, or 52 bytes offset for 32-bit.

    if (!result->disk_backed)
        my_flags->es_proc_missing_disk_backing == true; // Heuristic 3: Check the process is not backed by disk executable. More of an anomaly rather than a detection.

    if (!result->text_segment_present_disk)
        my_flags->es_proc_text_segment_missing_disk = true; // Heuristic 4: Check to see if the .text segment is present on disk. This should always be present unless the binary is still packed/obfuscated in memory.

    if (!result->text_segment_present_mem)
        my_flags->es_proc_text_segment_missing_mem = true; // Heuristic 5: Is the .text segment is present in memory. This should always be present unless the disk backed binary is packed/obfuscated.

    if (!result->entry_point_in_text)
        my_flags->es_proc_entry_points_not_in_text == true; // Heuristic 6: Check to see if the e_entry field does NOT point within the .text segment. This should always be the case apart from special cases such as ‘VBoxService’.

    if (!result->entry_points_match)
        my_flags->es_proc_entry_points_not_matching == true; // Heuristic 7: Check to see if the e_entry values for process & disk binary match.

    my_flags->es_proc_entry_fuzzy_score = result->entry_fuzzy_score; // Heuristic 8: Check the e_entry for the libc linked process matches the expected initialization code for ‘libc_start_main’. Highly suspicious unless this is for an interpreter process e.g. ‘/usr/bin/python’ OR container processes ‘/usr/sbin/VBoxService’

    // Heuristic 9:
    // process init/fini sections that don't appear in .text segment
    // process preinit/init/fini array functions that don't point within the .text segment.
    if (!result->proc_init_fini.fini_array_in_text ||
        !result->proc_init_fini.init_array_in_text ||
        !result->proc_init_fini.preinit_array_in_text ||
        !result->proc_init_fini.init_in_text ||
        !result->proc_init_fini.fini_in_text)
    {
        my_flags->es_proc_init_fini_not_in_text = true;
    }

    if (!result->proc_init_fini.init_at_text_start)
        my_flags->es_proc_init_not_at_text_start = true; // Heuristic 10: For processes it is expected the .init code block should begin at the start of the .text segment. NOTE: this is not expected for modules.

    // Iterate through each loaded module with similar heuristics.
    for (auto it = result->module_results.begin(); it != result->module_results.end(); ++it)
    {

        if (!(*it).disk_backed)
            my_flags->es_mod_missing_disk_backing = true; // Heuristic 11: Check to see if module is backed by disk executable. More of an anomaly rather than a detection. Check against every module.

        if (!(*it).entry_point_in_text)
            my_flags->es_mod_entry_points_not_in_text = true; // Heuristic 12: Check the e_entry field points within .text segment of the module. This should always be the case for modules. Check against every module

        if (!(*it).entry_points_match)
            my_flags->es_mod_entry_points_not_matching = true; // Heuristic 13: Check to see the e_entry values for module and disk match. Check against every module

        // Heuristic 14:
        // module init/fini sections that don't appear in .text segment
        // module preinit/init/fini array functions that don't point within the .text segment.
        // Checks against every module.
        if (!(*it).mod_init_fini.fini_array_in_text ||
            !(*it).mod_init_fini.init_array_in_text ||
            !(*it).mod_init_fini.preinit_array_in_text ||
            !(*it).mod_init_fini.fini_in_text ||
            !(*it).mod_init_fini.init_in_text)
        {
            my_flags->es_mod_init_fini_not_in_text = true;
        }
    }
}


void check_entry_config_settings(config my_config, es_flags my_flags, bool *add_result)
{
    if (my_flags.es_section_hdr_missing && my_config.es_section_hdr_missing)
        *add_result = true; // Heuristic 1 : Section headers can been stripped from a binary (this is suspicious but not necessarily malicious).

    if (my_flags.es_phdr_wrong_location && my_config.es_phdr_wrong_location)
        *add_result = true; // Heuristic 2: Check to see if if the program headers start in the expected place (immediately after the ELF32_Ehdr/ELF64_Ehdr) e.g. 64 bytes offset for 64-bit, or 52 bytes offset for 32-bit.

    if (my_flags.es_proc_missing_disk_backing && my_config.es_proc_missing_disk_backing)
        *add_result == true; // Heuristic 3: Check the process is not backed by disk executable. More of an anomaly rather than a detection.

    if (my_flags.es_proc_text_segment_missing_disk && my_config.es_proc_text_segment_missing_disk)
        *add_result = true; // Heuristic 4: Check to see if the .text segment is present on disk. This should always be present unless the binary is still packed/obfuscated in memory.

    if (my_flags.es_proc_text_segment_missing_mem && my_config.es_proc_text_segment_missing_mem)
        *add_result = true; // Heuristic 5: Is the .text segment is present in memory. This should always be present unless the disk backed binary is packed/obfuscated.

    if (my_flags.es_proc_entry_points_not_in_text && my_config.es_proc_entry_points_not_in_text)
        *add_result == true; // Heuristic 6: Check to see if the e_entry field does NOT point within the .text segment. This should always be the case apart from special cases such as ‘VBoxService’.

    if (my_flags.es_proc_entry_points_not_matching && my_config.es_proc_entry_points_not_matching)
        *add_result == true; // Heuristic 7: Check to see if the e_entry values for process & disk binary match.

    // If proc_entry_fuzzy_score is below my_config threshold then add result.
    if (my_flags.es_proc_entry_fuzzy_score <= my_config.es_proc_entry_fuzzy_score)
        *add_result = true; // Heuristic 8: Check the e_entry for the libc linked process matches the expected initialization code for ‘libc_start_main’. Highly suspicious unless this is for an interpreter process e.g. ‘/usr/bin/python’ OR container processes ‘/usr/sbin/VBoxService’

    // Heuristic 9:
    // process init/fini sections that don't appear in .text segment
    // process preinit/init/fini array functions that don't point within the .text segment.
    if (my_flags.es_proc_init_fini_not_in_text && my_config.es_proc_init_fini_not_in_text)
        *add_result = true;

    if (my_flags.es_proc_init_not_at_text_start && my_config.es_proc_init_not_at_text_start)
        *add_result = true; // Heuristic 10: For processes it is expected the .init code block should begin at the start of the .text segment. NOTE: this is not expected for modules.

    if (my_flags.es_mod_missing_disk_backing && my_config.es_mod_missing_disk_backing)
        *add_result = true; // Heuristic 11: Check to see if module is backed by disk executable. More of an anomaly rather than a detection. Check against every module.

    if (my_flags.es_mod_entry_points_not_in_text && my_config.es_mod_entry_points_not_in_text)
        *add_result = true; // Heuristic 12: Check the e_entry field points within .text segment of the module. This should always be the case for modules. Check against every module

    if (my_flags.es_mod_entry_points_not_matching && my_config.es_mod_entry_points_not_matching)
        *add_result = true; // Heuristic 13: Check to see the e_entry values for module and disk match. Check against every module

    // Heuristic 14:
    // module init/fini sections that don't appear in .text segment
    // module preinit/init/fini array functions that don't point within the .text segment.
    // Checks against every module.
    if (my_flags.es_mod_init_fini_not_in_text && my_config.es_mod_init_fini_not_in_text)
        *add_result = true;
}

void collect_entry_point_results_64(elf_info_64 elf_info, std::vector<entry_point_results> *entry_point_results_vector, config my_config)
{

    // Is pid still alive, this is vital.

    /* Validate data first, if false then quit
    if (!validate_data_64(elf_info_64))
    {
        printf("Validate\n");
        return;
    }
    */

    es_flags my_flags;
    entry_point_results result;
    bool add_result = false;

    // Populate our results vector with fields already collected by elf_info.cpp
    result.proc_start_time = elf_info.proc_start_time;
    result.pid = elf_info.pid;
    result.ppid = elf_info.ppid;
    result.hostname = elf_info.hostname;
    result.base_address = elf_info.base_vaddr;
    result.process_path = elf_info.process_path;
    result.cmdline = elf_info.cmdline;
    result.disk_backed = elf_info.disk_backed;
    result.shdr_off = elf_info.elf_mem_hdrs.ehdr_mem.e_shoff;
    result.phdr_off = elf_info.elf_mem_hdrs.ehdr_mem.e_phoff;
    result.dynamic_segment_present = elf_info.elf_mem_hdrs.dynamic_segment_present;
    result.text_segment_present_disk = elf_info.elf_disk_hdrs.text_pHdr_disk_present;
    result.text_segment_present_mem = elf_info.elf_mem_hdrs.text_pHdr_mem_present;

    if (elf_info.elf_mem_hdrs.phdr_irregular_location_mem || elf_info.elf_disk_hdrs.phdr_irregular_location_disk)
        result.manipulated_program_headers = true;

    // If we have a disk backed process & the process has a .text segment
    if (elf_info.disk_backed && elf_info.elf_mem_hdrs.text_pHdr_mem_present)
    {
        // Check to see if the e_entry fields match between disk & memory.
        // And if the e_entry points to within the .text segment in memory.
        compare_entry_64(elf_info.base_vaddr, elf_info.elf_mem_hdrs.ehdr_mem, elf_info.elf_mem_hdrs.text_pHdr_mem, elf_info.elf_disk_hdrs.ehdr_disk, &result.entry_points_match, &result.entry_point_in_text);
    }

    // If we have a dynamic segment & .text segment in memory
    if (elf_info.elf_mem_hdrs.dynamic_segment_present && elf_info.elf_mem_hdrs.text_pHdr_mem_present)
    {
        // Do the the dt_init, dt_fini, dt_init_array, dt_preinit_array and dt_fini_array functions reside within the .text segment.
        compare_init_fini_64(elf_info.pid, elf_info.base_vaddr, elf_info.elf_mem_hdrs.dyn_info_mem, elf_info.elf_mem_hdrs.text_pHdr_mem, &result.proc_init_fini);
    }

    // Now do the same for the module entries & init_fini sections.
    // Also determine if LIBC is linked, so we can perfrom entry point hashing later.
    if (!elf_info.elf_modules.empty())
    {
        for (auto it = elf_info.elf_modules.begin(); it != elf_info.elf_modules.end(); ++it)
        {

            // Identify if process has LIBC linked.
            if (std::string::npos != (*it).module_path.find("libc.so"))
                result.libc_present = true;

            module_entry module_result;
            module_result.disk_backed = (*it).disk_backed;
            module_result.module_path = (*it).module_path;

            // Compare module entry points
            if ((*it).disk_backed && (*it).elf_mem_hdrs.text_pHdr_mem_present)
            {
                compare_entry_64(elf_info.pid, (*it).elf_mem_hdrs.ehdr_mem, (*it).elf_mem_hdrs.text_pHdr_mem, (*it).elf_disk_hrds.ehdr_disk, &module_result.entry_points_match, &module_result.entry_point_in_text);
            }

            // Do the the module dt_init, dt_fini, dt_init_array, dt_preinit_array and dt_fini_array functions reside within the .text segment.
            if ((*it).elf_mem_hdrs.dynamic_segment_present && (*it).elf_mem_hdrs.text_pHdr_mem_present)
            {
                compare_init_fini_64(elf_info.pid, (*it).base_vaddr, (*it).elf_mem_hdrs.dyn_info_mem, (*it).elf_mem_hdrs.text_pHdr_mem, &module_result.mod_init_fini);
            }

            // Includes result if entry point or init/fini/preint funct is found to point outside of text segment
            // Special case for libc.so.
            if (filter_modules(module_result, module_result.mod_init_fini, module_result.module_path))
            {
                result.module_results.push_back(module_result);
            }
        }
    }

    // If no libc linked then result.entry_fuzzy_score is set by default at -1.
    if (result.libc_present)
    {
        result.entry_fuzzy_score = libc_entry_fuzzy_score_64(elf_info.pid, elf_info.elf_mem_hdrs.ehdr_mem.e_entry, elf_info.base_vaddr);
    }

    set_flags(&result, &my_flags);

    check_entry_config_settings(my_config, my_flags, &add_result);

    if (add_result)
    {
        // push back result into results vector.
        entry_point_results_vector->push_back(result);
    }
}

void *start_entry_point_thread_64(void *threadarg)
{

    entry_point_thread_data_64 *my_data;
    my_data = (entry_point_thread_data_64 *)threadarg;

    // Cycle through all elf_info_64_vectors given to a single thread.
    for (auto it = my_data->elf_info_64_vector->begin(); it != my_data->elf_info_64_vector->end(); ++it)
    {
        // Collect our results.
        collect_entry_point_results_64((*it), my_data->results_vector, my_data->my_config);
    }

    pthread_exit(NULL);
}

void entry_point_scanner_main_64(elf_info_64_group *elf_info_64_pots, config my_config)
{
    std::vector<entry_point_results> results_vector[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    entry_point_thread_data_64 td[THREAD_COUNT]; // Thread data needs be changed for specific to scanner results.
    pthread_attr_t attr;
    void *status;
    int rc;
    timespec start_time, end_time;
    time_t elapsed_seconds;
    long elapsed_nanoseconds;
    std::string output_filename = elf_info_64_pots->elf_info_64_pots[0][0].hostname + "_entry_point_scanner_output_64.json";

    printf("Starting entry point scanner x64\n");
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
        td[i].elf_info_64_vector = &elf_info_64_pots->elf_info_64_pots[i];
        td[i].results_vector = &results_vector[i];
        td[i].thread_id = i;

        // td[i].results_vector = results_vector; - TODO. This will have to be some kind of results template, since all scanners will have different results_vector type e.g. library_results_vector.

        // Create thread sending it to analyze_group function.
        rc = pthread_create(&threads[i], NULL, start_entry_point_thread_64, (void *)&td[i]);
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
    entry_point_results_writer(output_filename.c_str(), &results_vector[0]);

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

    printf("Finished entry point scanner x64\n");
    printf("Entry Point Scanner x64 runtime: %lu.%lus\n", elapsed_seconds, elapsed_nanoseconds);
}
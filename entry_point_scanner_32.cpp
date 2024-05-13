
#include "entry_point_scanner.h"

int libc_entry_fuzzy_score_32(pid_t pid, Elf64_Addr entry_address, Elf64_Addr base_vaddr)
{
    int fuzzy_score;
    char fuzzy_hash[FUZZY_MAX_RESULT];
    const char *expected_fuzzy_hash;
    unsigned char initialization_code[39];

    // Make sure entry point is an absolute virtual address.
    entry_address = (base_vaddr > entry_address) ? (base_vaddr + entry_address) : entry_address;

    // Read size of initialization code from memory e_entry
    if (process_read(pid, initialization_code, (const void *)entry_address, 39))
    {
        printf("Failed to initialization code with process_read() in function 'libc_entry_fuzzy_score_32': %s for pid: %i\n", strerror(errno), pid);
        return false;
    }

    // for <_start> that calls <__libc_start_main@plt>
    initialization_code[16] = 0x00;
    initialization_code[17] = 0x00;
    initialization_code[18] = 0x00;
    initialization_code[19] = 0x00;

    initialization_code[22] = 0x00;
    initialization_code[23] = 0x00;
    initialization_code[24] = 0x00;
    initialization_code[25] = 0x00;

    initialization_code[28] = 0x00;
    initialization_code[29] = 0x00;
    initialization_code[30] = 0x00;
    initialization_code[31] = 0x00;

    initialization_code[35] = 0x00;
    initialization_code[36] = 0x00;
    initialization_code[37] = 0x00;
    initialization_code[38] = 0x00;

    expected_fuzzy_hash = "3:BX79XvX7XN/:BX7RrN/";

    // Generate fuzzy hash
    fuzzy_hash_buf((const unsigned char *)initialization_code, 39, fuzzy_hash);

    /*
	printf("PID: %i	EntryAddress: 0X%lx	Fuzz:%s\n", pid, entry_address, fuzzy_hash);
	printf("InitCode:	");

	for (int i = 0; i < 39; i++)
	{
		printf("%02x ", initialization_code[i]);
	}
	printf("\n");
    */

    // Compare fuzzy has against hard coded fuzzy hash score.
    fuzzy_score = fuzzy_compare(fuzzy_hash, expected_fuzzy_hash);

    return fuzzy_score;
}

void compare_entry_32(Elf64_Addr base_vaddr, Elf32_Ehdr ehdr_mem, Elf32_Phdr text_pHdr_mem, Elf32_Ehdr ehdr_disk, bool *entry_points_match, bool *entry_point_in_text)
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

void compare_init_fini_32(pid_t pid, Elf32_Addr base_vaddr, dynamic_info32 dynamic_info, Elf32_Phdr text_pHdr_mem, init_fini_comparisions *init_fini_result)
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

        if (process_read(pid, dt_preinit_array_mem, (void *)(uint64_t)dynamic_info.dt_preinit_array, dynamic_info.dt_preinit_arraysz) == -1)
        {
            printf("Failed to read preinitArray with process_read() in function 'compare_init_fini_32': %s\n", strerror(errno));
            return;
        }

        // Iterate through preinitArray addresses to make sure they point within the text section.
        Elf32_Addr function_pointer;
        int number_of_function_pointers = dynamic_info.dt_preinit_array / sizeof(Elf32_Addr);

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

        if (process_read(pid, dt_init_array_mem, (void *)(uint64_t)dynamic_info.dt_init_array, dynamic_info.dt_init_arraysz) == -1)
        {
            printf("Failed to read initArray with process_read() in function 'compare_init_fini_32': %s\n", strerror(errno));
            return;
        }

        Elf32_Addr function_pointer;
        // Iterate through initArray addresses to make sure they point within the text section.
        int number_of_function_pointers = dynamic_info.dt_init_arraysz / sizeof(Elf32_Addr);

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

        if (process_read(pid, dt_fini_array_mem, (void *)(uint64_t)dynamic_info.dt_fini_array, dynamic_info.dt_fini_arraysz) == -1)
        {
            printf("Failed to read finiArray with process_read() in function 'compare_init_fini_32': %s\n", strerror(errno));
            return;
        }

        Elf32_Addr function_pointer;
        int number_of_function_pointers = dynamic_info.dt_fini_arraysz / sizeof(Elf32_Addr);

        init_fini_result->number_of_fini_array_funcs = number_of_function_pointers;

        for (int k = 0; k < number_of_function_pointers; k++)
        {
            function_pointer = dt_fini_array_mem[k];

            if (!sits_within(function_pointer, text_pHdr_mem.p_vaddr, (text_pHdr_mem.p_vaddr + text_pHdr_mem.p_memsz)))
                init_fini_result->fini_array_in_text = false;
        }
    }
}

void collect_entry_point_results_32(elf_info_32 elf_info, std::vector<entry_point_results> *entry_point_results_vector, config my_config)
{

    // Is pid still alive, this is vital.

    /* Validate data first, if false then quit
    if (!validate_data_64(elf_info_64))
    {
        printf("Validate\n");
        return;
    }
    */

    entry_point_results result;
    es_flags my_flags;
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
        compare_entry_32(elf_info.base_vaddr, elf_info.elf_mem_hdrs.ehdr_mem, elf_info.elf_mem_hdrs.text_pHdr_mem, elf_info.elf_disk_hdrs.ehdr_disk, &result.entry_points_match, &result.entry_point_in_text);
    }

    // If we have a dynamic segment & .text segment in memory
    if (elf_info.elf_mem_hdrs.dynamic_segment_present && elf_info.elf_mem_hdrs.text_pHdr_mem_present)
    {
        // Do the the dt_init, dt_fini, dt_init_array, dt_preinit_array and dt_fini_array functions reside within the .text segment.
        compare_init_fini_32(elf_info.pid, elf_info.base_vaddr, elf_info.elf_mem_hdrs.dyn_info_mem, elf_info.elf_mem_hdrs.text_pHdr_mem, &result.proc_init_fini);
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
                compare_entry_32(elf_info.pid, (*it).elf_mem_hdrs.ehdr_mem, (*it).elf_mem_hdrs.text_pHdr_mem, (*it).elf_disk_hrds.ehdr_disk, &module_result.entry_points_match, &module_result.entry_point_in_text);
            }

            // Do the the module dt_init, dt_fini, dt_init_array, dt_preinit_array and dt_fini_array functions reside within the .text segment.
            if ((*it).elf_mem_hdrs.dynamic_segment_present && (*it).elf_mem_hdrs.text_pHdr_mem_present)
            {
                compare_init_fini_32(elf_info.pid, (*it).base_vaddr, (*it).elf_mem_hdrs.dyn_info_mem, (*it).elf_mem_hdrs.text_pHdr_mem, &module_result.mod_init_fini);
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
        result.entry_fuzzy_score = libc_entry_fuzzy_score_32(elf_info.pid, elf_info.elf_mem_hdrs.ehdr_mem.e_entry, elf_info.base_vaddr);
    }

    set_flags(&result, &my_flags);

    check_entry_config_settings(my_config, my_flags, &add_result);

    if (add_result)
    {
        // push back result into results vector.
        entry_point_results_vector->push_back(result);
    }
}

void *start_entry_point_thread_32(void *threadarg)
{

    entry_point_thread_data_32 *my_data;
    my_data = (entry_point_thread_data_32 *)threadarg;

    // Cycle through all elf_info_64_vectors given to a single thread.
    for (auto it = my_data->elf_info_32_vector->begin(); it != my_data->elf_info_32_vector->end(); ++it)
    {
        // Collect our results.
        collect_entry_point_results_32((*it), my_data->results_vector, my_data->my_config);
    }

    pthread_exit(NULL);
}

void entry_point_scanner_main_32(elf_info_32_group *elf_info_32_pots, config my_config)
{
    std::vector<entry_point_results> results_vector[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    entry_point_thread_data_32 td[THREAD_COUNT]; // Thread data needs be changed for specific to scanner results.
    pthread_attr_t attr;
    void *status;
    int rc;
    timespec start_time, end_time;
    time_t elapsed_seconds;
    long elapsed_nanoseconds;
    std::string output_filename = elf_info_32_pots->elf_info_32_pots[0][0].hostname + "_entry_point_scanner_output_32.json";

    printf("Starting entry point scanner x86\n");
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
        rc = pthread_create(&threads[i], NULL, start_entry_point_thread_32, (void *)&td[i]);
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

    printf("Finished entry point scanner x86\n");
    printf("Entry Point Scanner x86 runtime: %lu.%lus\n", elapsed_seconds, elapsed_nanoseconds);
}
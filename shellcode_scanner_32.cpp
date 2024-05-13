#include "shellcode_scanner.h"

bool get_fuzzy_hash_mem_32(pid_t pid, Elf32_Addr base_vaddr, Elf32_Phdr text_pHdr_mem, std::string &fuzzy_hash, uint16_t e_type)
{

    char fuzzy_hash_mem[FUZZY_MAX_RESULT];

    void *process_text_segment = calloc(1, text_pHdr_mem.p_memsz);

    // Executables (ET_EXEC) always use the absolute base address.
    // Shared object (ET_DYN) compiled executables use relative addressing. So the base address needs to be added.
    if (e_type == ET_EXEC)
    {
        if (process_read(pid, process_text_segment, (const void *)(uint64_t)text_pHdr_mem.p_vaddr, text_pHdr_mem.p_memsz))
        {
            printf("Failed to read process .text section with process_read() in function collect_shellcode_results_64: %s for pid: %i\n", strerror(errno), pid);
            return false;
        }
    }
    else if (e_type == ET_DYN)
    {
        if (process_read(pid, process_text_segment, (const void *)(uint64_t)(base_vaddr + text_pHdr_mem.p_vaddr), text_pHdr_mem.p_memsz))
        {
            printf("Failed to read process .text section with process_read() in function collect_shellcode_results_64: %s for pid: %i\n", strerror(errno), pid);
            return false;
        }
    }

    // Error here!
    fuzzy_hash_buf((const unsigned char *)(process_text_segment), text_pHdr_mem.p_memsz, fuzzy_hash_mem);

    fuzzy_hash = fuzzy_hash_mem;

    free(process_text_segment);

    return true;
}

bool get_fuzzy_hash_disk_32(pid_t pid, std::string file_name, Elf32_Phdr text_pHdr_disk, std::string &fuzzy_hash)
{

    char fuzzy_hash_disk[FUZZY_MAX_RESULT];

    int fd;
    struct stat st;
    size_t mapSize;
    uint8_t *mem;

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

    // Error here!
    if (read(fd, mem, mapSize) == -1)
    {
        printf("Disk Read Failed in get_headers_and_segment_info_disk: %s for pid: %i\n", strerror(errno), pid);
        close(fd);
        free(mem);
        return false;
    }

    void *disk_text_segment = calloc(1, text_pHdr_disk.p_filesz);
    memcpy(disk_text_segment, (mem + text_pHdr_disk.p_offset), text_pHdr_disk.p_filesz);

    // Error here with avahi chroot helper process.
    fuzzy_hash_buf((const unsigned char *)(disk_text_segment), text_pHdr_disk.p_filesz, fuzzy_hash_disk);

    fuzzy_hash = fuzzy_hash_disk;

    free(disk_text_segment);
    free(mem);
    close(fd);

    return true;
}

void collect_shellcode_results_32(elf_info_32 elf_info, std::vector<shellcode_results> *shellcode_results_vector, config my_config)
{

    // Is pid still alive, this is vital.

    /* Validate data first, if false then quit
    if (!validate_data_64(elf_info))
    {
        printf("Validate\n");
        return;
    }
    */
    bool add_result = false;
    ss_flags my_flags;

    shellcode_results result;
    // char fuzzy_hash_mem[FUZZY_MAX_RESULT];
    // char fuzzy_hash_disk[FUZZY_MAX_RESULT];

    std::string fuzzy_hash_mem;
    std::string fuzzy_hash_disk;

    // Populate our results vector with fields already collected by elf_info.cpp
    result.proc_start_time = elf_info.proc_start_time;
    result.pid = elf_info.pid;
    result.ppid = elf_info.ppid;
    result.hostname = elf_info.hostname;
    result.process_path = elf_info.process_path;
    result.cmdline = elf_info.cmdline;
    result.disk_backed = elf_info.disk_backed;
    result.proc_number_of_headers_mem = elf_info.elf_mem_hdrs.ehdr_mem.e_phnum;
    result.proc_number_of_headers_disk = elf_info.elf_disk_hdrs.ehdr_disk.e_phnum;
    result.process_rwx_header_present_mem = elf_info.elf_mem_hdrs.rwx_or_wx_header_present_mem;
    result.process_rwx_header_present_disk = elf_info.elf_disk_hdrs.rwx_or_wx_header_present_disk;
    result.dynamic_segment_present = elf_info.elf_mem_hdrs.dynamic_segment_present;

    /* Now generate results for
        result.memfd_anonymous_mapping_found;
        result.proc_text_score
        result.allModuleScores
     */

    if (!result.disk_backed)
       my_flags.ss_proc_missing_disk_backing = true; // Heuristic 1 : Process missing disk backed binary.

    if (result.proc_number_of_headers_mem != result.proc_number_of_headers_disk)
       my_flags.ss_proc_phdr_memory_disk_mismatch = true; // Heuristic 2: The number of process program headers in memory should equal that of its corresponding disk binary.

    if (result.process_rwx_header_present_mem)
       my_flags.ss_rwx_present_disk = true; // Heuristic 3 : Process memory contains a segment with Read/write & execute permissions.

    if (result.process_rwx_header_present_disk)
       my_flags.ss_rwx_present_mem = true; // Heuristic 4 : Process binary contains a segment with Read/write & execute permissions.

    if (!result.dynamic_segment_present)
       my_flags.ss_dynamic_segment_missing = true; // Heuristic 5 : Dynamic segment missing. Can indicate packing.

    // If process path contains /memfd: then it has been mapped using memfd_create() function.
    // A bash script to find this would be "ls -alR /proc/*/exe 2> /dev/null | grep memfd:.*\(deleted\)"
    if (std::string::npos != elf_info.process_path.find("memfd:"))
    {
        result.memfd_anonymous_mapping_found = true;
       my_flags.ss_memfd_mapping_found = false; // Heuristic 6 : Process loaded directly from memory using memfd_create()
    }

    // If the process has a .text segment in both memory and on disk then attempt to compare.
    if (elf_info.elf_mem_hdrs.text_pHdr_mem_present && elf_info.elf_disk_hdrs.text_pHdr_disk_present)
    {
        // If the process is backed by a file then generate fuzzy hash comparision between memory and disk .text (RX) segments.
        if (elf_info.disk_backed)
        {
            // get fuzzy hash of process memory .text segment.
            get_fuzzy_hash_mem_32(elf_info.pid, elf_info.base_vaddr, elf_info.elf_mem_hdrs.text_pHdr_mem, fuzzy_hash_mem, elf_info.elf_mem_hdrs.ehdr_mem.e_type);

            // get fuzzy hash of disk .text segment.
            get_fuzzy_hash_disk_32(elf_info.pid, elf_info.process_path, elf_info.elf_disk_hdrs.text_pHdr_disk, fuzzy_hash_disk);

            // Generate fuzzy hash score & save in result.
            get_fuzzy_hash_score(fuzzy_hash_mem.c_str(), fuzzy_hash_disk.c_str(), &result.proc_text_score);

           my_flags.ss_proc_score = result.proc_text_score; // Heuristic 11: This measures the similarity between process disk & memory text (RX) segments. A low score indicates significant changes (and thus possible injection of code).
        }
    }

    // If the process has modules then perform the same hashing.
    if (!elf_info.elf_modules.empty())
    {

        for (auto it = elf_info.elf_modules.begin(); it != elf_info.elf_modules.end(); ++it)
        {

            module_fuzzy module_score;

            module_score.module_path = (*it).module_path;
            module_score.base_address = (*it).base_vaddr;
            module_score.disk_backed = (*it).disk_backed;
            module_score.mod_number_of_headers_disk = (*it).elf_disk_hrds.ehdr_disk.e_phnum;
            module_score.mod_number_of_headers_mem = (*it).elf_mem_hdrs.ehdr_mem.e_phnum;
            module_score.mod_rwx_header_present_disk = (*it).elf_disk_hrds.rwx_or_wx_header_present_disk;
            module_score.mod_rwx_header_present_mem = (*it).elf_mem_hdrs.rwx_or_wx_header_present_mem;

            if (!module_score.disk_backed)
               my_flags.ss_mod_missing_disk_backing = true; // Heuristic 7 : module missing disk backed binary. Check for all modules

            if (module_score.mod_number_of_headers_disk != module_score.mod_number_of_headers_mem)
               my_flags.ss_mod_phdr_memory_disk_mismatch = true; // Heuristic 8: The number of module program headers in memory should equal that of its corresponding disk binary. Any mismatch indicates a segment has either been added or taken away in memory. Check for all modules.

            if (module_score.mod_rwx_header_present_disk)
               my_flags.ss_mod_rwx_header_present_disk = true; // Heuristic 9 : Module memory contains a segment with Read/write & execute permissions. Check for all modules.

            if (module_score.mod_number_of_headers_mem)
               my_flags.ss_mod_rwx_header_present_mem = true; // Heuristic 10 : Module binary contains a segment with Read/write & execute permissions. Check for all modules.

            // Skip to next module if there is no disk backing, no text pHdr in memory OR no text pHdr on disk
            if ((!(*it).disk_backed) || (!(*it).elf_mem_hdrs.text_pHdr_mem_present) || (!(*it).elf_disk_hrds.text_pHdr_disk_present))
            {
                result.module_scores.push_back(module_score);
                continue;
            }

            std::string mod_fuzzy_hash_mem;
            std::string mod_fuzzy_hash_disk;

            // get fuzzy hash of process memory .text segment.
            get_fuzzy_hash_mem_32(elf_info.pid, (*it).base_vaddr, (*it).elf_mem_hdrs.text_pHdr_mem, mod_fuzzy_hash_mem, (*it).elf_mem_hdrs.ehdr_mem.e_type);

            // get fuzzy hash of disk .text segment.
            get_fuzzy_hash_disk_32(elf_info.pid, (*it).module_path, (*it).elf_disk_hrds.text_pHdr_disk, mod_fuzzy_hash_disk);

            // Generate fuzzy hash score & save in result.
            get_fuzzy_hash_score(mod_fuzzy_hash_mem.c_str(), mod_fuzzy_hash_disk.c_str(), &module_score.mod_text_score);

            // Record lowest fuzzy hash score.
            if ((module_score.mod_text_score != -1) && (module_score.mod_text_score < my_flags.ss_lowest_mod_score))
               my_flags.ss_lowest_mod_score = module_score.mod_text_score; // Heuristic 12: This measures the similarity between module disk & memory text (RX) segments. A low score indicates significant changes (and thus possible injection of code).

            result.module_scores.push_back(module_score);
        }
    }

    check_shellcode_config_settings(my_config, my_flags, &add_result);

    if (add_result)
    {
        // pushback result into results vector.
        shellcode_results_vector->push_back(result);
    }
}

void *start_shellcode_thread_32(void *threadarg)
{

    shellcode_thread_data_32 *my_data;
    my_data = (shellcode_thread_data_32 *)threadarg;

    // Cycle through all elf_info_64_vectors given to a single thread.
    for (auto it = my_data->elf_info_32_vector->begin(); it != my_data->elf_info_32_vector->end(); ++it)
    {
        // Collect our results.
        collect_shellcode_results_32((*it), my_data->results_vector, my_data->my_config);
    }

    pthread_exit(NULL);
}

void shellcode_scanner_main_32(elf_info_32_group *elf_info_32_pots, config my_config)
{
    std::vector<shellcode_results> results_vector[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    shellcode_thread_data_32 td[THREAD_COUNT]; // Thread data needs be changed for specific to scanner results.
    pthread_attr_t attr;
    void *status;
    int rc;
    timespec start_time, end_time;
    time_t elapsed_seconds;
    long elapsed_nanoseconds;
    std::string output_filename = elf_info_32_pots->elf_info_32_pots[0][0].hostname + "_shellcode_scanner_output_32.json";

    printf("Starting shellcode scanner x86\n");
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

        // td[i].results_vector = results_vector; - TODO. This will have to be some kind of results template, since all scanners will have different results_vector type e.g. shellcode_results_vector.

        // Create thread sending it to analyze_group function.
        rc = pthread_create(&threads[i], NULL, start_shellcode_thread_32, (void *)&td[i]);
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
    shellcode_results_writer(output_filename.c_str(), &results_vector[0]);

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

    printf("Finished shellcode scanner x86\n");
    printf("Shellcode scanner x86 runtime: %lu.%lus\n", elapsed_seconds, elapsed_nanoseconds);
}
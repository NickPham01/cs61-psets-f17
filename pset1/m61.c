#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

int debug = 0;

// Global to store stats data, initialize all values to 0
struct m61_statistics mem_stats = {0, 0, 0, 0, 0, 0, 0, 0};

// Define struct to hold metadata
struct metadata {
    size_t mem_size;
    int isfreed;    // active low: malloc sets isfreed to 1, free sets it back to zero.
};

int meta_struct_size = sizeof(struct metadata);

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    // meta_ptr points to beginning of allocation, where metadata will be stored in a struct
    struct metadata* meta_ptr = base_malloc(sz + meta_struct_size);

    // payload_ptr points to the actual memory requested when m61_malloc is called
    void* payload_ptr = meta_ptr + meta_struct_size;

    // Check for failure
    if (meta_ptr == NULL || sz >= (size_t) -1) {
        payload_ptr = NULL;

        // Update Statistics
        mem_stats.nfail++;
        mem_stats.fail_size += sz;
    }
    else {
        // Update Statistics
        mem_stats.nactive++;
        mem_stats.active_size += sz;
        mem_stats.ntotal++;
        mem_stats.total_size += sz;


        if (!mem_stats.heap_min || mem_stats.heap_min > (char*) payload_ptr) {
            mem_stats.heap_min = payload_ptr;
        }

        if (!mem_stats.heap_max || mem_stats.heap_max < (char*) payload_ptr + sz) {
            mem_stats.heap_max = payload_ptr + sz;
        }
        
        // Record metadata
        meta_ptr -> mem_size = sz;
        meta_ptr -> isfreed = 1;
    }
//// DEBUG!!!!
if (debug) {
    printf("malloc size = %zu\n", meta_ptr -> mem_size);
    printf("metadata addr = %p\n", meta_ptr);
    printf("payload addr = %p\n\n", payload_ptr);
}
    return payload_ptr;
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.

void m61_free(void *ptr, const char *file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    // Only free if not NULL
    if(ptr) {

        struct metadata* meta_ptr = ptr - meta_struct_size * 0x10;
////DEBUG!!!!
if(debug) {
    printf("free size = %zu\n", meta_ptr -> mem_size);
    printf("metadata addr = %p\n", meta_ptr);
    printf("payload addr = %p\n\n", ptr);
}
        // Check if ptr is in the heap
        if ((char*) ptr < mem_stats.heap_min    /* check if ptr is below the heap */
            || (char*) ptr > mem_stats.heap_max) { /* check if ptr is above the heap */
            //|| meta_ptr -> isfreed != 1) {      /* check if ptr has already been freed */
            printf("MEMORY BUG %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
        }

        else {          

            // Update Statistics
            mem_stats.nactive--;
            mem_stats.active_size -= meta_ptr -> mem_size;    // ptr points to metadata

            // Update Metadata
            meta_ptr -> isfreed = 0;    // indicate that this memory has already been freed
           
            base_free(ptr);
        }
    }
}


/// m61_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `m61_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `m61_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

void* m61_realloc(void* ptr, size_t sz, const char* file, int line) {
    void* new_ptr = NULL;
    if (sz) {
        new_ptr = m61_malloc(sz, file, line);
    }
    if (ptr && new_ptr) {
        // Copy the data from `ptr` into `new_ptr`.
        // To do that, we must figure out the size of allocation `ptr`.
        // Your code here (to fix test014).
        
        // Read old size from metadata
        struct metadata* old_meta = ptr - meta_struct_size * 0x10;
        size_t old_sz = old_meta -> mem_size;

        if (old_sz < sz)
            memcpy(new_ptr, ptr, old_sz);
        else
            memcpy(new_ptr, ptr, sz);
    }
    m61_free(ptr, file, line);
    return new_ptr;
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, int line) {
    // Your code here (to fix test016).
////DEBUG!!!!
if (debug) {
    printf("%zx\n", (size_t) - 1);
    printf("%zx\n", (size_t) -1 / 8);
    printf("%zx\n\n", (size_t) -1 / 8 + 2);

    printf("%x\n",- 1);
    printf("%x\n",-1 / 8);
    printf("%x\n",-1 / 8 + 2);
}

    size_t size = nmemb * sz;

    // There was an integer overflow, as sz >= 1;
    if (size < nmemb)
        size = (size_t) -1;    // Set size to a very large value, which m61_malloc rejects

    void* ptr = m61_malloc(size, file, line);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}


/// m61_getstatistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_getstatistics(struct m61_statistics* stats) {
    stats -> nactive = mem_stats.nactive;
    stats -> active_size = mem_stats.active_size;
    stats -> ntotal = mem_stats.ntotal;
    stats -> total_size = mem_stats.total_size;
    stats -> nfail = mem_stats.nfail;
    stats -> fail_size = mem_stats.fail_size;
    stats -> heap_min = mem_stats.heap_min;
    stats -> heap_max = mem_stats.heap_max;
}


/// m61_printstatistics()
///    Print the current memory statistics.

void m61_printstatistics(void) {
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_printleakreport(void) {
    // Your code here.
}

#ifndef PROXY_HASHMAP_H
#define PROXY_HASHMAP_H
#include <time.h>

#define START_ENTRY_CAPACITY 256
#define MAX_ENTRY_CAPACITY 1024 * 1024 * 1024

typedef struct data_entry_t {
    time_t cached_time;
    char *data;
    // мб сменить на связный список
    size_t data_size;
    pthread_mutex_t mutex;
    pthread_cond_t condition;

    int whole;
    int incorrect ;
    int capacity;
} data_entry_t;

typedef struct HashMap HashMap;

HashMap* create_hashmap();

/**
 * return 0 if success
 * 1 if smth went bad...
 */
int insert_entry(HashMap *hashmap, const char *key, const char *value);

/**
 * 0 if success
 * 1 if not
 */
int insert_replace_value_in_hashmap(HashMap *hashmap, const char *key, const char *value);


int get_data_from_hashmap(HashMap *hashmap, const char *key, char *ret_data, time_t *contained_time);


/**
 * if hashmap doesn't contain needed key, we do nothing
 * if hashmap contains needed key, we seize whole hashmap, so nobody else can touch it
 */
int seize_hashmap(HashMap *hashmap, const char *key, char *ret_data, time_t *contained_time);

/**
 * needed after seizing hashmap
 */
void unseize_hashmap(HashMap *hashmap);


data_entry_t *seize_entry(HashMap *hashmap, const char *key);

void unseize_entry(data_entry_t *entry);

int write_to_entry(data_entry_t *data_entry, char *buffer, size_t len_to_write);

int read_from_entry(data_entry_t *data_entry, char *responce_buffer, size_t alredy_read, size_t want_to_read);

void entry_set_whole(data_entry_t *data_entry);

void entry_set_incorrect(data_entry_t *data_entry);

int is_entry_whole(data_entry_t *data_entry);

int entry_data_size(data_entry_t *data_entry);

#endif //PROXY_HASHMAP_H
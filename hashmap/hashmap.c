#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <malloc.h>
#include <fcntl.h>
#include <ucontext.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>

#include "hashmap.h"



#define HASHTABLE_SIZE 100

#define seed_for_murmur 12345678


// typedef struct data_entry_t {
//     time_t cached_time;
//     char *data;
//     // мб сменить на связный список
//     size_t data_size;
//     pthread_mutex_t mutex;
//     pthread_cond_t condition;
// } data_entry_t;


typedef struct HashNode {
    char *key;

    // //cached data
    // time_t cached_time;
    // char *data;
    // // мб сменить на связный список
    // size_t data_size;
    // pthread_mutex_t mutex;
    // //cached data

    data_entry_t *data_entry;

    struct HashNode *next;
    
} HashNode;

typedef struct HashMap {
    // int capacity;
    int cur_size;
    pthread_rwlock_t rwlock;
    HashNode **table;
} HashMap;

HashNode *create_hash_node(char *key, char* value);
size_t __calculate_capacity(size_t val_size);

HashMap* create_hashmap() {
    HashMap *hash_map = (HashMap *) malloc(sizeof(HashMap));
    if (hash_map == NULL) {
        printf("error whie malloc()\n");
        pthread_exit(NULL);
    }
    hash_map->table = (HashNode **) malloc(sizeof(HashNode *) * HASHTABLE_SIZE);
    pthread_rwlock_init(&hash_map->rwlock, NULL);

    for (int i = 0; i < HASHTABLE_SIZE; ++i) {
        hash_map->table[i] = NULL;
    }
    hash_map->cur_size = HASHTABLE_SIZE;
    return hash_map;
}


uint32_t rotl32(uint32_t x, int8_t r) {
    return (x << r) | (x >> (32 - r));
}

//  len = len of key
uint32_t murmurhash3_32(const void *key) {
    uint32_t seed = seed_for_murmur;
    size_t len = strlen(key);
    const uint8_t *data = (const uint8_t *)key;
    const size_t nblocks = len / 4;
    uint32_t h1 = seed;

    // Обработка блоков по 4 байта
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    
    for (size_t i = 0; i < nblocks; ++i) {
        uint32_t k1;
        memcpy(&k1, data + i * 4, sizeof(uint32_t));
        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    // Обработка оставшихся байтов
    uint32_t k1 = 0;
    const size_t tail_index = nblocks * 4;
    switch (len & 3) {
        case 3: k1 ^= data[tail_index + 2] << 16;
        case 2: k1 ^= data[tail_index + 1] << 8;
        case 1: k1 ^= data[tail_index];
                k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2; h1 ^= k1;
    }

    // Финализируем хеш
    h1 ^= len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

uint32_t hash(const char *key) {
    return murmurhash3_32(key) % HASHTABLE_SIZE;
}


/**
 * return 0 if success
 * 1 if smth went bad...
 */
int insert_entry(HashMap *hashmap, const char *key, const char *value) {
    int inserted;

    unsigned int index = hash(key);
    HashNode *new_node = create_hash_node(key, value);
    if (new_node == NULL) {
        return 1;
    }

    pthread_rwlock_wrlock(&hashmap->rwlock);
    // here we insert new node to hashmap
    if (hashmap->table[index] == NULL) {
        hashmap->table[index] = new_node;
        hashmap->cur_size++;
        pthread_rwlock_unlock(&hashmap->rwlock);
        return 0;
    }

    HashNode *cur = hashmap->table[index];
    while (cur) {
        if (strcmp(cur->key, new_node->key) == 0) {
            pthread_rwlock_unlock(&hashmap->rwlock);
            return 1;
        }
        cur = cur->next;
    }

    new_node->next = hashmap->table[index];
    hashmap->table[index] = new_node;
    hashmap->cur_size++;
    pthread_rwlock_unlock(&hashmap->rwlock);
    return 0;
}

/**
 * 0 if success
 * 1 if not
 */
int insert_replace_value_in_hashmap(HashMap *hashmap, const char *key, const char *value) {
    unsigned int index = hash(key);
    
    pthread_rwlock_wrlock(&hashmap->rwlock);


    HashNode *cur = hashmap->table[index];
    while (cur) {
        if (strcmp(cur->key, key) == 0) {
            break;
        }
        cur = cur->next;
    }
    if (cur == NULL) {
        printf("problems trying to find existing entry...\nso gonne create new one\n");
        pthread_rwlock_unlock(&hashmap->rwlock);
        return insert_entry(hashmap, key, value);
    }
    // if we are here it means cur != NULL, we find it

    cur->data_entry->data_size = strlen(value);
    cur->data_entry->data = (char *) realloc(cur->data_entry->data, strlen(value));
    if (cur->data_entry->data == NULL) {
        printf("error while realloc\n");
        return 1;
    }
    memset(cur->data_entry->data, 0, cur->data_entry->data_size);
    strcpy(cur->data_entry->data, value);

    pthread_rwlock_unlock(&hashmap->rwlock);
    return 0;
}

/**
 * allocate memory for hash-node and set all needed values
 */
HashNode *create_hash_node(char *key, char* value) {
    HashNode *node = (HashNode *) malloc(sizeof(HashNode));
    node->key = strdup(key);
    node->data_entry = (data_entry_t *) malloc(sizeof(data_entry_t));
    pthread_mutex_init(&node->data_entry->mutex, NULL);
    pthread_cond_init(&(node->data_entry->condition), NULL);
    if (value != NULL) {
        // hashmap do not support too big entries
        if (strlen(value) > MAX_ENTRY_CAPACITY) {
            pthread_mutex_destroy(&node->data_entry->mutex);
            pthread_cond_destroy(&(node->data_entry->condition));
            return NULL;
        }
        node->data_entry->data = malloc(strlen(value));
        if (node->data_entry->data == NULL) {
            pthread_mutex_destroy(&node->data_entry->mutex);
            pthread_cond_destroy(&(node->data_entry->condition));
            return NULL;
        }
        node->data_entry->data_size = strlen(value);
        node->data_entry->capacity = strlen(value);
        memset(node->data_entry->data, 0, node->data_entry->data_size);
        memcpy(node->data_entry->data, value, strlen(value));
    } else {
        node->data_entry->data = NULL;
        node->data_entry->data_size = 0;
        node->data_entry->capacity = 0;
    }
    
    node->data_entry->cached_time = time(NULL);
    node->data_entry->incorrect = 0;

    node->next = NULL;
    return node;
}


/**
 * return 1 if success
 * 0 if there is no entry with that key
 */
int get_data_from_hashmap(HashMap *hashmap, const char *key, char *ret_data, time_t *contained_time) {
    uint32_t index = hash(key);

    pthread_rwlock_rdlock(&hashmap->rwlock);
    HashNode *cur = hashmap->table[index];
    while (cur) {
        if (strcmp(cur->key, key) == 0) {
            memcpy(ret_data, cur->data_entry->data, cur->data_entry->data_size);
            *contained_time = time(NULL) - cur->data_entry->cached_time;
            pthread_rwlock_unlock(&hashmap->rwlock);
            return 1;
        }
        cur = cur->next;
    }

    pthread_rwlock_unlock(&hashmap->rwlock);
    return 0;
}

int seize_hashmap(HashMap *hashmap, const char *key, char *ret_data, time_t *contained_time) {
    uint32_t index = hash(key);

    pthread_rwlock_rdlock(&hashmap->rwlock);
    HashNode *cur = hashmap->table[index];
    while (cur) {
        if (strcmp(cur->key, key) == 0) {
            memcpy(ret_data, cur->data_entry->data, cur->data_entry->data_size);
            *contained_time = time(NULL) - cur->data_entry->cached_time;
            return 1;
        }
        cur = cur->next;
    }

    pthread_rwlock_unlock(&hashmap->rwlock);
    return 0;
}



void unseize_hashmap(HashMap *hashmap) {
    pthread_rwlock_unlock(&hashmap->rwlock);
}

/**
 * return pointer to data_entry , asking for the key
 * if not found entry with such key, return NULL
 */
data_entry_t *seize_entry(HashMap *hashmap, const char *key) {
    uint32_t index = hash(key);

    pthread_rwlock_rdlock(&hashmap->rwlock);
    HashNode *cur = hashmap->table[index];
    while (cur) {
        if (strcmp(cur->key, key) == 0) {
            data_entry_t *ret = cur->data_entry;
            pthread_rwlock_unlock(&hashmap->rwlock);
            pthread_mutex_lock(&ret->mutex);
            return ret;
        }
        cur = cur->next;
    }

    pthread_rwlock_unlock(&hashmap->rwlock);
    return NULL;
}

void unseize_entry(data_entry_t *entry) {
    pthread_mutex_unlock(&entry->mutex);
}



/**
 * copy <=want_to_read bytes to responce_buffer from data_entry
 * already_read - how much of entry_read was already read
 * return number of read on success
 * 
 * if data in enrty gone bad - also return -1
 * return -1 if error
 */
int read_from_entry(data_entry_t *data_entry, char *responce_buffer, size_t alredy_read, size_t want_to_read) {
    pthread_mutex_lock(&data_entry->mutex);

    //if there is no data we can read NAD data correct - we gonna wait
    while (data_entry->data_size <= alredy_read && data_entry->incorrect == 0) {
        pthread_cond_wait(&data_entry->condition, &data_entry->mutex);
    }
    if (data_entry->incorrect == 1) {
        pthread_mutex_unlock(&data_entry->mutex);
        return -1;
    }

    int gonna_read = (data_entry->data_size - alredy_read >= want_to_read) ? want_to_read : data_entry->data_size - alredy_read;
    memcpy(responce_buffer, data_entry->data, gonna_read);
    pthread_mutex_unlock(&data_entry->mutex);
    return gonna_read;

}


size_t __calculate_capacity(size_t val_size) {
    int start = START_ENTRY_CAPACITY;
    while (val_size > start) {
        start *= 2;
    }
    return start;
}

/**
 * return 0 if success,
 * return 1 if error
 */
int write_to_entry(data_entry_t *data_entry, char *buffer, size_t len_to_write) {
    pthread_mutex_lock(&data_entry->mutex);

    data_entry->whole = 0;
    data_entry->incorrect = 0;

    if (len_to_write + data_entry->data_size > MAX_ENTRY_CAPACITY) {
        pthread_mutex_unlock(&data_entry->mutex);
        return 1;
    }

    int needed = __calculate_capacity(len_to_write + data_entry->data_size);
    if (needed > data_entry->capacity) {
        data_entry->data = realloc(data_entry->data, needed);
        if (data_entry->data == NULL) {
            // ???
            data_entry->incorrect = 0;
            pthread_mutex_unlock(&data_entry->mutex);
            return 1;
        }  

        data_entry->capacity = needed;
        
    }
    memcpy(data_entry->data, buffer, len_to_write);
    data_entry->data_size += len_to_write;
    pthread_cond_broadcast(&data_entry->condition);
    pthread_mutex_unlock(&data_entry->mutex);
    return 0;
    
} 


void entry_set_whole(data_entry_t *data_entry) {
    pthread_mutex_lock(&data_entry->mutex);
    data_entry->whole = 1;
    pthread_mutex_unlock(&data_entry->mutex);
}


void entry_set_incorrect(data_entry_t *data_entry) {
    pthread_mutex_lock(&data_entry->mutex);
    data_entry->incorrect = 1;
    pthread_mutex_unlock(&data_entry->mutex);
}


int is_entry_whole(data_entry_t *data_entry) {
    pthread_mutex_lock(&data_entry->mutex);
    int res = data_entry->whole;
    pthread_mutex_unlock(&data_entry->mutex);
    return res;
}

int entry_data_size(data_entry_t *data_entry) {
    int res = -1;
    pthread_mutex_lock(&data_entry->mutex);
    if (data_entry->whole) {
        res = data_entry->data_size;
    }
    pthread_mutex_unlock(&data_entry->mutex);
    return res;
}
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_FBK_HASH_H_
#define _RTE_FBK_HASH_H_

/**
 * @file
 *
 * This is a hash table implementation for four byte keys (fbk).
 *
 * Note that the return value of the add function should always be checked as,
 * if a bucket is full, the key is not added even if there is space in other
 * buckets. This keeps the lookup function very simple and therefore fast.
 */

#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

#include <rte_config.h>
#include <rte_hash_crc.h>
#include <rte_jhash.h>

#ifndef RTE_FBK_HASH_INIT_VAL_DEFAULT
/** Initialising value used when calculating hash. */
#define RTE_FBK_HASH_INIT_VAL_DEFAULT		0xFFFFFFFF
#endif

/** The maximum number of entries in the hash table that is supported. */
#define RTE_FBK_HASH_ENTRIES_MAX		(1 << 20)

/** The maximum number of entries in each bucket that is supported. */
#define RTE_FBK_HASH_ENTRIES_PER_BUCKET_MAX	256

/** Maximum size of string for naming the hash. */
#define RTE_FBK_HASH_NAMESIZE			32

/** Type of function that can be used for calculating the hash value. */
typedef uint32_t (*rte_fbk_hash_fn)(uint32_t key, uint32_t init_val);

/** Parameters used when creating four-byte key hash table. */
struct rte_fbk_hash_params {
	const char *name;		/**< Name of the hash table. */
	uint32_t entries;		/**< Total number of entries. */
	uint32_t entries_per_bucket;	/**< Number of entries in a bucket. */
	int socket_id;			/**< Socket to allocate memory on. */
	rte_fbk_hash_fn hash_func;	/**< The hash function. */
	uint32_t init_val;		/**< For initialising hash function. */
};

/** Individual entry in the four-byte key hash table. */
union rte_fbk_hash_entry {
	uint64_t whole_entry;		/**< For accessing entire entry. */
	struct {
		uint16_t is_entry;	/**< Non-zero if entry is active. */
		uint16_t value;		/**< Value returned by lookup. */
		uint32_t key;		/**< Key used to find value. */
	} entry;			/**< For accessing each entry part. */
};


/** The four-byte key hash table structure. */
struct rte_fbk_hash_table {
	char name[RTE_FBK_HASH_NAMESIZE];	/**< Name of the hash. */
	uint32_t entries;		/**< Total number of entries. */
	uint32_t entries_per_bucket;	/**< Number of entries in a bucket. */
	uint32_t used_entries;		/**< How many entries are used. */
	uint32_t bucket_mask;		/**< To find which bucket the key is in. */
	uint32_t bucket_shift;		/**< Convert bucket to table offset. */
	rte_fbk_hash_fn hash_func;	/**< The hash function. */
	uint32_t init_val;		/**< For initialising hash function. */

	/** A flat table of all buckets. */
	union rte_fbk_hash_entry t[];
};

/**
 * Find the offset into hash table of the bucket containing a particular key.
 *
 * @param ht
 *   Pointer to hash table.
 * @param key
 *   Key to calculate bucket for.
 * @return
 *   Offset into hash table.
 */
static inline uint32_t
rte_fbk_hash_get_bucket(const struct rte_fbk_hash_table *ht, uint32_t key)
{
	return (ht->hash_func(key, ht->init_val) & ht->bucket_mask) <<
			ht->bucket_shift;
}

/**
 * Add a key to an existing hash table with bucket id.
 * This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param ht
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param value
 *   Value to associate with key.
 * @param bucket
 *   Bucket to associate with key.
 * @return
 *   0 if ok, or negative value on error.
 */
static inline int
rte_fbk_hash_add_key_with_bucket(struct rte_fbk_hash_table *ht,
			uint32_t key, uint16_t value, uint32_t bucket)
{
	/*
	 * The writing of a new value to the hash table is done as a single
	 * 64bit operation. This should help prevent individual entries being
	 * corrupted due to race conditions, but it's still possible to
	 * overwrite entries that have just been made valid.
	 */
	const uint64_t new_entry = ((uint64_t)(key) << 32) |
			((uint64_t)(value) << 16) |
			1;  /* 1 = is_entry bit. */
	uint32_t i;

	for (i = 0; i < ht->entries_per_bucket; i++) {
		/* Set entry if unused. */
		if (! ht->t[bucket + i].entry.is_entry) {
			ht->t[bucket + i].whole_entry = new_entry;
			ht->used_entries++;
			return 0;
		}
		/* Change value if key already exists. */
		if (ht->t[bucket + i].entry.key == key) {
			ht->t[bucket + i].entry.value = value;
			return 0;
		}
	}

	return -ENOSPC; /* No space in bucket. */
}

/**
 * Add a key to an existing hash table. This operation is not multi-thread safe
 * and should only be called from one thread.
 *
 * @param ht
 *   Hash table to add the key to.
 * @param key
 *   Key to add to the hash table.
 * @param value
 *   Value to associate with key.
 * @return
 *   0 if ok, or negative value on error.
 */
static inline int
rte_fbk_hash_add_key(struct rte_fbk_hash_table *ht,
			uint32_t key, uint16_t value)
{
	return rte_fbk_hash_add_key_with_bucket(ht,
				key, value, rte_fbk_hash_get_bucket(ht, key));
}

/**
 * Remove a key with a given bucket id from an existing hash table.
 * This operation is not multi-thread
 * safe and should only be called from one thread.
 *
 * @param ht
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @param bucket
 *   Bucket id associate with key.
 * @return
 *   0 if ok, or negative value on error.
 */
static inline int
rte_fbk_hash_delete_key_with_bucket(struct rte_fbk_hash_table *ht,
					uint32_t key, uint32_t bucket)
{
	uint32_t last_entry = ht->entries_per_bucket - 1;
	uint32_t i, j;

	for (i = 0; i < ht->entries_per_bucket; i++) {
		if (ht->t[bucket + i].entry.key == key) {
			/* Find last key in bucket. */
			for (j = ht->entries_per_bucket - 1; j > i; j-- ) {
				if (! ht->t[bucket + j].entry.is_entry) {
					last_entry = j - 1;
				}
			}
			/*
			 * Move the last key to the deleted key's position, and
			 * delete the last key. lastEntry and i may be same but
			 * it doesn't matter.
			 */
			ht->t[bucket + i].whole_entry =
					ht->t[bucket + last_entry].whole_entry;
			ht->t[bucket + last_entry].whole_entry = 0;

			ht->used_entries--;
			return 0;
		}
	}

	return -ENOENT; /* Key didn't exist. */
}

/**
 * Remove a key from an existing hash table. This operation is not multi-thread
 * safe and should only be called from one thread.
 *
 * @param ht
 *   Hash table to remove the key from.
 * @param key
 *   Key to remove from the hash table.
 * @return
 *   0 if ok, or negative value on error.
 */
static inline int
rte_fbk_hash_delete_key(struct rte_fbk_hash_table *ht, uint32_t key)
{
	return rte_fbk_hash_delete_key_with_bucket(ht,
				key, rte_fbk_hash_get_bucket(ht, key));
}

/**
 * Find a key in the hash table with a given bucketid.
 * This operation is multi-thread safe.
 *
 * @param ht
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @param bucket
 *   Bucket associate to the key.
 * @return
 *   The value that was associated with the key, or negative value on error.
 */
static inline int
rte_fbk_hash_lookup_with_bucket(const struct rte_fbk_hash_table *ht,
				uint32_t key, uint32_t bucket)
{
	union rte_fbk_hash_entry current_entry;
	uint32_t i;

	for (i = 0; i < ht->entries_per_bucket; i++) {
		/* Single read of entry, which should be atomic. */
		current_entry.whole_entry = ht->t[bucket + i].whole_entry;
		if (! current_entry.entry.is_entry) {
			return -ENOENT; /* Error once we hit an empty field. */
		}
		if (current_entry.entry.key == key) {
			return current_entry.entry.value;
		}
	}
	return -ENOENT; /* Key didn't exist. */
}

/**
 * Find a key in the hash table. This operation is multi-thread safe.
 *
 * @param ht
 *   Hash table to look in.
 * @param key
 *   Key to find.
 * @return
 *   The value that was associated with the key, or negative value on error.
 */
static inline int
rte_fbk_hash_lookup(const struct rte_fbk_hash_table *ht, uint32_t key)
{
	return rte_fbk_hash_lookup_with_bucket(ht,
				key, rte_fbk_hash_get_bucket(ht, key));
}

/**
 * Delete all entries in a hash table. This operation is not multi-thread
 * safe and should only be called from one thread.
 *
 * @param ht
 *   Hash table to delete entries in.
 */
static inline void
rte_fbk_hash_clear_all(struct rte_fbk_hash_table *ht)
{
	memset(ht->t, 0, sizeof(ht->t[0]) * ht->entries);
	ht->used_entries = 0;
}

/**
 * Find what fraction of entries are being used.
 *
 * @param ht
 *   Hash table to find how many entries are being used in.
 * @return
 *   Load factor of the hash table, or negative value on error.
 */
static inline double
rte_fbk_hash_get_load_factor(struct rte_fbk_hash_table *ht)
{
	return (double)ht->used_entries / (double)ht->entries;
}

/**
 * Performs a lookup for an existing hash table, and returns a pointer to
 * the table if found.
 *
 * @param name
 *   Name of the hash table to find
 *
 * @return
 *   pointer to hash table structure or NULL on error with rte_errno
 *   set appropriately. Possible rte_errno values include:
 *    - ENOENT - required entry not available to return.
 */
struct rte_fbk_hash_table *rte_fbk_hash_find_existing(const char *name);

/**
 * Create a new hash table for use with four byte keys.
 *
 * @param params
 *   Parameters used in creation of hash table.
 *
 * @return
 *   Pointer to hash table structure that is used in future hash table
 *   operations, or NULL on error with rte_errno set appropriately.
 *   Possible rte_errno error values include:
 *    - E_RTE_NO_CONFIG - function could not get pointer to rte_config structure
 *    - E_RTE_SECONDARY - function was called from a secondary process instance
 *    - EINVAL - invalid parameter value passed to function
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
struct rte_fbk_hash_table * \
rte_fbk_hash_create(const struct rte_fbk_hash_params *params);

/**
 * Free all memory used by a hash table.
 * Has no effect on hash tables allocated in memory zones
 *
 * @param ht
 *   Hash table to deallocate.
 */
void rte_fbk_hash_free(struct rte_fbk_hash_table *ht);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_FBK_HASH_H_ */

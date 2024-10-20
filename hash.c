// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich, Marek Lindner
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "hash.h"
#include <stdlib.h>
#include <stdio.h>

/* clears the hash */
void hash_init(struct hashtable_t *hash)
{
	int i;

	hash->elements = 0;

	for (i = 0; i < hash->size; i++)
		hash->table[i] = NULL;
}

/* remove the hash structure. if hashdata_free_cb != NULL,
 * this function will be called to remove the elements inside of the hash.
 * if you don't remove the elements, memory might be leaked.
 */
void hash_delete(struct hashtable_t *hash, hashdata_free_cb free_cb)
{
	struct element_t *last_bucket;
	struct element_t *bucket;
	int i;

	for (i = 0; i < hash->size; i++) {
		bucket = hash->table[i];
		while (bucket) {
			if (free_cb)
				free_cb(bucket->data);

			last_bucket = bucket;
			bucket = bucket->next;
			free(last_bucket);
		}
	}

	hash_destroy(hash);
}

/* adds data to the hashtable and reuse bucket.
 * returns 0 on success, -1 on error
 */
static int hash_add_bucket(struct hashtable_t *hash, void *data,
			   struct element_t *bucket, int check_duplicate)
{
	struct element_t *prev_bucket = NULL;
	struct element_t *bucket_it;
	int index;

	index = hash->choose(data, hash->size);
	bucket_it = hash->table[index];

	while (bucket_it) {
		if (check_duplicate &&
		    hash->compare(bucket_it->data, data))
			return -1;

		prev_bucket = bucket_it;
		bucket_it = bucket_it->next;
	}

	/* init the new bucket */
	bucket->data = data;
	bucket->next = NULL;

	/* and link it */
	if (!prev_bucket)
		hash->table[index] = bucket;
	else
		prev_bucket->next = bucket;

	hash->elements++;
	return 0;
}

/* free only the hashtable and the hash itself. */
void hash_destroy(struct hashtable_t *hash)
{
	free(hash->table);
	free(hash);
}

/* free hash_it_t pointer when stopping hash_iterate early */
void hash_iterate_free(struct hash_it_t *iter_in)
{
	free(iter_in);
}

/* iterate though the hash. first element is selected with iter_in NULL.
 * use the returned iterator to access the elements until hash_it_t returns
 * NULL.
 */
struct hash_it_t *hash_iterate(struct hashtable_t *hash,
			       struct hash_it_t *iter_in)
{
	struct hash_it_t *iter;

	if (!iter_in) {
		iter = malloc(sizeof(*iter));
		if (!iter)
			return NULL;

		iter->index =  -1;
		iter->bucket = NULL;
		iter->prev_bucket = NULL;
	} else {
		iter = iter_in;
	}

	/* sanity checks first (if our bucket got deleted in the last
	 * iteration):
	 */
	if (iter->bucket) {
		if (iter->first_bucket) {
			/* we're on the first element and it got removed after
			 * the last iteration.
			 */
			if ((*iter->first_bucket) != iter->bucket) {
				/* there are still other elements in the list */
				if ((*iter->first_bucket) != NULL) {
					iter->prev_bucket = NULL;
					iter->bucket = (*iter->first_bucket);
					iter->first_bucket = &hash->table[iter->index];
					return iter;
				}

				iter->bucket = NULL;
			}

		} else if (iter->prev_bucket) {
			/* we're not on the first element, and the bucket got
			 * removed after the last iteration. The last bucket's
			 * next pointer is not pointing to our actual bucket
			 * anymore. Select the next.
			 */
			if (iter->prev_bucket->next != iter->bucket)
				iter->bucket = iter->prev_bucket;
		}
	}

	/* now as we are sane, select the next one if there is some */
	if (iter->bucket) {
		if (iter->bucket->next) {
			iter->prev_bucket = iter->bucket;
			iter->bucket = iter->bucket->next;
			iter->first_bucket = NULL;
			return iter;
		}
	}
	/* if not returned yet, we've reached the last one on the index and
	 * have to search forward
	 */

	iter->index++;
	/* go through the entries of the hash table */
	while (iter->index < hash->size) {
		if (!hash->table[iter->index]) {
			iter->index++;
			continue;
		}

		iter->prev_bucket = NULL;
		iter->bucket = hash->table[iter->index];
		iter->first_bucket = &hash->table[iter->index];
		return iter;	/* if this table entry is not null, return it */
	}

	/* nothing to iterate over anymore */
	hash_iterate_free(iter);
	return NULL;
}

/* allocates and clears the hash */
struct hashtable_t *hash_new(int size, hashdata_compare_cb compare,
			     hashdata_choose_cb choose)
{
	struct hashtable_t *hash;

	hash = malloc(sizeof(*hash));
	if (!hash)
		return NULL;

	hash->size = size;
	hash->table = calloc(size, sizeof(struct element_t *));

	if (!hash->table) {
		free(hash);
		return NULL;
	}

	hash_init(hash);
	hash->compare = compare;
	hash->choose = choose;
	return hash;
}

/* adds data to the hashtable. returns 0 on success, -1 on error */
int hash_add(struct hashtable_t *hash, void *data)
{
	struct element_t *bucket;
	int ret;

	/* found the tail of the list, add new element */
	bucket = malloc(sizeof(*bucket));

	if (!bucket)
		return -1;

	ret = hash_add_bucket(hash, data, bucket, 1);
	if (ret < 0)
		free(bucket);

	return ret;
}

/* finds data, based on the key in keydata. returns the found data on success,
 * or NULL on error
 */
void *hash_find(struct hashtable_t *hash, void *keydata)
{
	struct element_t *bucket;
	int index;

	index = hash->choose(keydata, hash->size);
	bucket = hash->table[index];

	while (bucket) {
		if (hash->compare(bucket->data, keydata))
			return bucket->data;

		bucket = bucket->next;
	}

	return NULL;
}

/* remove bucket (this might be used in hash_iterate() if you already found
 * the bucket you want to delete and don't need the overhead to find it again
 * with hash_remove(). But usually, you don't want to use this function, as it
 * fiddles with hash-internals.
 */
void *hash_remove_bucket(struct hashtable_t *hash, struct hash_it_t *hash_it_t)
{
	void *data_save;

	/* save the pointer to the data */
	data_save = hash_it_t->bucket->data;

	if (hash_it_t->prev_bucket)
		hash_it_t->prev_bucket->next = hash_it_t->bucket->next;
	else if (hash_it_t->first_bucket)
		(*hash_it_t->first_bucket) = hash_it_t->bucket->next;

	free(hash_it_t->bucket);

	hash->elements--;
	return data_save;
}

/* removes data from hash, if found. returns pointer do data on success,
 * so you can remove the used structure yourself, or NULL on error .
 * data could be the structure you use with just the key filled,
 * we just need the key for comparing.
 */
void *hash_remove(struct hashtable_t *hash, void *data)
{
	struct hash_it_t hash_it_t;

	hash_it_t.index = hash->choose(data, hash->size);
	hash_it_t.bucket = hash->table[hash_it_t.index];
	hash_it_t.prev_bucket = NULL;

	while (hash_it_t.bucket) {
		if (hash->compare(hash_it_t.bucket->data, data)) {
			int bucket_same;

			bucket_same = (hash_it_t.bucket ==
				       hash->table[hash_it_t.index]);
			hash_it_t.first_bucket = (bucket_same ?
						  &hash->table[hash_it_t.index] :
						  NULL);
			return hash_remove_bucket(hash, &hash_it_t);
		}

		hash_it_t.prev_bucket = hash_it_t.bucket;
		hash_it_t.bucket = hash_it_t.bucket->next;
	}

	return NULL;
}

/* resize the hash, returns the pointer to the new hash or NULL on error.
 * removes the old hash on success.
 */
struct hashtable_t *hash_resize(struct hashtable_t *hash, int size)
{
	struct hashtable_t *new_hash;
	struct element_t *bucket;
	int i;

	/* initialize a new hash with the new size */
	new_hash = hash_new(size, hash->compare, hash->choose);
	if (!new_hash)
		return NULL;

	/* copy the elements */
	for (i = 0; i < hash->size; i++) {
		while (hash->table[i]) {
			bucket = hash->table[i];
			hash->table[i] = bucket->next;
			hash_add_bucket(new_hash, bucket->data, bucket, 0);
		}
	}
	/* remove hash and eventual overflow buckets but not the
	 * content itself.
	 */
	hash_delete(hash, NULL);
	return new_hash;
}

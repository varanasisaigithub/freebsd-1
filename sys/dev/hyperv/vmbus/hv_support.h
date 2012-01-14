/*
 * hv_support.h
 *
 *  Created on: Jan 13, 2012
 *      Author: Larry Melia
 */

// todo ************** add proper banner here ***************

#ifndef __HV_SUPPORT_H__
#define __HV_SUPPORT_H__

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>

/**
 * Create a spin lock structure.
 *
 * @param spin_name used to identify the lock in debugging output and
 * 	by the witness code to classify a mutex when doing checks of
 *  	lock ordering.
 */
static inline struct mtx *
hv_mtx_create(const char *spin_name) {
	struct mtx *spin = malloc(sizeof(struct mtx), M_DEVBUF, M_ZERO | M_NOWAIT);
	if(spin != NULL) {
		mtx_init(spin, spin_name, NULL, MTX_SPIN | MTX_RECURSE);
	}
	return spin;
}

/**
 * Destroy a spin lock structure.
 */
static inline void
hv_mtx_destroy(struct mtx *mtx_struct) {
	if(mtx_struct != NULL) {
		mtx_destroy(mtx_struct);
		free(mtx_struct, M_DEVBUF);
	}
}

#endif /* HV_SUPPORT_H_ */

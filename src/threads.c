/*
**
** Copyright (c) 2010-2016 The SquirrelMail Project Team
** Copyright (c) 2002-2010 Dave McMurtrie
**
** Licensed under the GNU GPL. For full terms see the file COPYING.
**
** This file is part of SquirrelMail IMAP Proxy.
**
**  Facility:
**
**      threads.c
**
**  Abstract:
**
**      Routines to provide threadsafe interaction with OpenSSL libraries.
**
**  Authors:
**
**      Dave McMurtrie <davemcmurtrie@hotmail.com>
**
**  Version:
**
**      $Id$
**
**  Modification History:
**
**      $Log$
**
**      Revision 1.2  2007/05/31 11:58:17  dave64
**      Added license information and updated comment block.
**
**
*/

#define _REENTRANT

#include <config.h>

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#if defined(OPENSSL_THREADS)


#include <stdio.h>
#include <syslog.h>
#include <pthread.h>

#include <openssl/crypto.h>

#include "common.h"
#include "imapproxy.h"

static void locking_function(int mode, int n, const char *file, int line);
static unsigned long id_function(void);

static pthread_mutex_t *locks;

/* We use pthreads, since the rest of squirrelmail-imap_proxy does. */

void ssl_thread_setup(const char *fn) {
    int i, rc;

    syslog(LOG_NOTICE, "Initialising %d pthread_mutexes", CRYPTO_num_locks() );
    locks = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (locks == NULL) {
        syslog(LOG_ERR, "Cannot allocate space for SSL mutexes");
        exit(1);
    }

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        rc = pthread_mutex_init(&locks[i], NULL);
        if ( rc ) {
            syslog(LOG_ERR, "%s: pthread_mutex_init() returned error [%d] initializing OpenSSL mutexes.  Exiting.", fn, rc );
            exit( 1 );
        }
    }

    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
}

void locking_function(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&locks[n]);
    else
        pthread_mutex_unlock(&locks[n]);
}

unsigned long id_function(void) {
    return (unsigned long) pthread_self();
}


#else	/* defined(OPENSSL_THREADS) */
   #error OpenSSL compiled without thread support
#endif	/* defined(OPENSSL_THREADS) */

/*
 *                            _________
 *                           /        |
 *                          /         |
 *                         /    ______|
 *                        /    /       ________
 *                       |    |        |      /
 *                       |    |        |_____/
 *                       |    |        ______
 *                       |    |        |     \
 *                       |    |        |______\
 *                        \    \_______
 *                         \           |
 *                          \          |
 *                           \_________|
 */

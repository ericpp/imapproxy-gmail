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
**	icc.c
**
**  Abstract:
**
**	Routines to manipulate IMAP Connection Context structures.
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
**	Revision 1.8  2005/06/15 12:02:08  dgm
**	Include config.h.
**
**	Revision 1.7  2005/06/07 12:02:36  dgm
**	Conditionally include unistd.h (for close prototype).  Clean
**	up a few unused variables.
**
**	Revision 1.6  2004/02/24 15:14:44  dgm
**	Send LOGOUT to server when closing a connection.
**
**	Revision 1.5  2003/05/20 18:46:49  dgm
**	Comment changes only.
**
**	Revision 1.4  2003/05/06 12:11:12  dgm
**	Applied patches by Ken Murchison <ken@oceana.com> to include SSL support.
**
**	Revision 1.3  2002/12/17 14:23:12  dgm
**	Added support for global configuration structure.
**
**	Revision 1.2  2002/08/28 15:55:13  dgm
**	replaced all internal logging calls with standard syslog calls.
**
**	Revision 1.1  2002/07/03 12:06:58  dgm
**	Initial revision
**
*/


#define _REENTRANT

#include <config.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "common.h"
#include "imapproxy.h"

/*
 * External globals
 */
extern ICC_Struct *ICC_free;
extern ICC_Struct *ICC_HashTable[ HASH_TABLE_SIZE ];
extern pthread_mutex_t mp;
extern IMAPCounter_Struct *IMAPCount;
extern ProxyConfig_Struct PC_Struct;

/*
 * internal prototypes
 */
static void _ICC_Recycle( unsigned int );



/*++
 * Function:	_ICC_Recycle
 *
 * Purpose:	core logic to implement the ICC_Recycle() & ICC_Recycle_Loop()
 *              functions.
 *
 * Parameters:	unsigned int -- ICC expiration time
 *
 * Returns:	nada
 *	
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
static void _ICC_Recycle( unsigned int Expiration )
{
    time_t CurrentTime;
    unsigned int HashIndex;
    ICC_Struct *HashEntry;
    ICC_Struct *Previous;
    
    CurrentTime = time(0);

    LockMutex( &mp );
    
    /*
     * Need to iterate through every single item in our hash table
     * to decide if we can free it or not.
     */
    for ( HashIndex = 0; HashIndex < HASH_TABLE_SIZE; HashIndex++ )
    {
	
	Previous = NULL;
	HashEntry = ICC_HashTable[ HashIndex ];
	
	while ( HashEntry )
	{
	    /*
	     * If the last logout time is non-zero, and it's been logged 
	     * out for longer than our default expiration time, free it.
	     * Note that this allows for the logouttime to be explicitly
	     * set to 1 (such as in the Get_Server_conn code) if we want to
	     * reap a connection before waiting the normal expiration
	     * cycle.
	     */
	    if ( HashEntry->logouttime &&
		 ( ( CurrentTime - HashEntry->logouttime ) > 
		   Expiration ) )
	    {
		syslog(LOG_INFO, "Expiring server sd [%d]", HashEntry->server_conn->sd);
		/* Logout of the IMAP server and close the server socket. */

		IMAP_Write( HashEntry->server_conn, "VIC20 LOGOUT\r\n",
			    strlen( "VIC20 LOGOUT\r\n" ) );

#if HAVE_LIBSSL
		if ( HashEntry->server_conn->tls )
		{
		    SSL_shutdown( HashEntry->server_conn->tls );
		    SSL_free( HashEntry->server_conn->tls );
		}
#endif
		close( HashEntry->server_conn->sd );
		free( HashEntry->server_conn );
		
		/*
		 * This was being counted as a "retained" connection.  It was
		 * open, but not in use.  Now that we're closing it, we have
		 * to decrement the number of retained connections.
		 */
		IMAPCount->RetainedServerConnections--;
		

		if ( Previous )
		{
		    Previous->next = HashEntry->next;
		    HashEntry->next = ICC_free;
		    ICC_free = HashEntry;
		    HashEntry = Previous->next;
		}
		else
		{
		    ICC_HashTable[ HashIndex ] = HashEntry->next;
		    HashEntry->next = ICC_free;
		    ICC_free = HashEntry;
		    HashEntry = ICC_HashTable[ HashIndex ];
		}
	    }
	    else
	    {
		Previous = HashEntry;
		HashEntry = HashEntry->next;
	    }
	}
    }
    
    UnLockMutex( &mp );
}



/*++
 * Function:	ICC_Recycle
 *
 * Purpose:	Reclaim dormant ICC structures.  This function is intended to
 *              be called any time a free ICC is needed, but none exist.  It
 *              can be passed shorter than default expiration durations to try
 *              to free more ICCs if necessary.
 *
 * Parameters:	unsigned int -- ICC expiration duration
 *
 * Returns:	nada
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
extern void ICC_Recycle( unsigned int Expiration )
{
    _ICC_Recycle( Expiration );
}



/*++
 * Function:	ICC_Recycle_Loop
 *
 * Purpose:	Reclaim dormant ICC structures.  This function is intended
 *              to be run continuously as a single thread.
 *
 * Parameters:	nada
 *
 * Returns:	nada
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:       Relies on global copy of ProxyConfig_Struct "PC_Struct" for
 *              expiration time.
 *--
 */
extern void ICC_Recycle_Loop( void )
{
    for( ;; )
    {
	sleep( 60 );
	_ICC_Recycle( PC_Struct.cache_expiration_time );
    }
}



/*++
 * Function:	ICC_Logout
 *
 * Purpose:	set the last logout time for an IMAP connection context.
 *
 * Parameters:	char *Username
 *		int server-side socket descriptor
 *		
 * Returns:	nada
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
extern void ICC_Logout( ICC_Struct *ICC )
{
    IMAPCount->InUseServerConnections--;
    IMAPCount->RetainedServerConnections++;

    if ( IMAPCount->RetainedServerConnections > 
	 IMAPCount->PeakRetainedServerConnections )
	IMAPCount->PeakRetainedServerConnections = IMAPCount->RetainedServerConnections;
    
    ICC->logouttime = time(0);

    syslog(LOG_INFO, "LOGOUT: '%s' from server sd [%d]", ICC->username, ICC->server_conn->sd );
    
    return;
}

void _ICC_Invalidate ( ICC_Struct *ICC )
{
    #if HAVE_LIBSSL
    if ( ICC->server_conn->tls ) {
        SSL_shutdown( ICC->server_conn->tls );
        SSL_free( ICC->server_conn->tls );
    }
    #endif

    close( ICC->server_conn->sd );

    ICC->server_conn->sd = -1; /* make sure this can't be reused */
    ICC->logouttime = 1;
}

extern void ICC_Invalidate ( ICC_Struct *ICC )
{
    LockMutex( &mp );
    _ICC_Invalidate ( ICC );
    UnLockMutex( &mp );
}


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

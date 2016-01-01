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
**	imapcommon.c
**
**  Abstract:
**
**	Routines common to making IMAP server connections and receiving
**	data from an IMAP server or client. 
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
**	Revision 1.25  2008/10/20 13:23:04  dave64
**	Applied patch by Michael M. Slusarz to support XPROXYREUSE.
**
**	Revision 1.24  2007/05/31 12:09:46  dave64
**	Applied ipv6 patch by Antonio Querubin.
**
**	Revision 1.23  2007/05/31 11:50:49  dave64
**	Patch by Matt Selsky (include openssl/md5.h) to prevent compilation
**	failure with newer OpenSSL versions.
**
**	Revision 1.22  2006/08/15 13:13:08  dave64
**	No longer exit() from IMAP_Line_Read.  Just return failure.
**
**	Revision 1.21  2005/06/15 12:06:31  dgm
**	Added missing include directive for openssl/err.h.
**	atoui function added to replace calls to atoi.
**	Include limits.h and config.h.
**
**	Revision 1.20  2005/01/12 17:50:16  dgm
**	Applied patch by David Lancaster to provide force_tls
**	config option.
**
**	Revision 1.19  2004/11/10 15:29:23  dgm
**	Explicitly NULL terminate all strings that are the result of
**	strncpy.  Also enforce checking of LiteralBytesRemaining
**	after any calls to IMAP_Line_Read.
**
**	Revision 1.18  2003/10/22 13:39:24  dgm
**	Fixed really bad bug in for loop for string literal detection.
**	Explicitly clear errno prior to calling atol().
**
**	Revision 1.17  2003/10/09 12:53:49  dgm
**	Added source port to syslog messages.  Added ability to send
**	tcp keepalives.  Added a poll() call in IMAP_Literal_Read() so
**	read calls can't block forever.
**
**	Revision 1.16  2003/07/14 16:37:44  dgm
**	Applied patch by William Yodlowsky <wyodlows@andromeda.rutgers.edu>
**	to allow TLS to work without /dev/random.
**
**	Revision 1.15  2003/05/20 18:49:53  dgm
**	Comment changes only.
**
**	Revision 1.14  2003/05/15 11:47:59  dgm
**	Added code to deal with possible unsolicited, untagged capability
**	response from server in Get_Server_conn().  Added credit comment in
**	function header block, also.
**
**	Revision 1.13  2003/05/13 14:19:27  dgm
**	Changed AF_INET constant reference to PF_INET.
**
**	Revision 1.12  2003/05/13 11:39:58  dgm
**	Patches by Ken Murchison <ken@oceana.com> to clean up build process.
**
**	Revision 1.11  2003/05/06 12:09:57  dgm
**	Applied patches by Ken Murchison <ken@oceana.com> to add SSL support.
**
**	Revision 1.10  2003/02/20 13:52:16  dgm
**	Logic changed in Get_Server_sd() such that authentication is attempted to the
**	real server when the md5 checksums don't match instead of just dropping
**	the connection.
**
**	Revision 1.9  2003/02/19 12:47:31  dgm
**	Replaced check for server response of "+ go ahead" with a check for
**	"+".  the "go ahead" appears to be cyrus specific and not RFC compliant
**	on my part.
**
**	Revision 1.8  2003/01/27 13:59:53  dgm
**	Patch by Frode Nordahl <frode@powertech.no> to allow
**	compilation on Linux platforms.
**
**	Revision 1.7  2003/01/23 16:24:31  dgm
**	NonSyncLiteral flag was not being cleared properly.
**
**	Revision 1.6  2003/01/22 12:56:30  dgm
**	Changes to Get_Server_sd() so it can support login attempts where
**	the client sends the password as a string literal.
**
**	Revision 1.5  2002/12/18 14:39:55  dgm
**	Fixed bug in for loop for string literal processing.
**
**	Revision 1.4  2002/12/17 14:22:41  dgm
**	Added support for global configuration structure.
**
**	Revision 1.3  2002/08/29 20:22:12  dgm
**	Fixed nasty socket descriptor leak.
**
**	Revision 1.2  2002/08/28 15:57:49  dgm
**	replaced all internal log function calls with standard syslog calls.
**
**	Revision 1.1  2002/07/03 12:07:26  dgm
**	Initial revision
**
*/


#define _REENTRANT

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <syslog.h>
#include <poll.h>

#include "common.h"
#include "imapproxy.h"

/*
 * External globals
 */
extern ICC_Struct *ICC_free;
extern ICC_Struct *ICC_HashTable[ HASH_TABLE_SIZE ];
extern ISD_Struct ISD;
extern pthread_mutex_t mp;
extern pthread_mutex_t trace;
extern IMAPCounter_Struct *IMAPCount;
extern ProxyConfig_Struct PC_Struct;

#if HAVE_LIBSSL
extern SSL_CTX *tls_ctx;

/*++
 * Function:	SSLerrmessage
 *
 * Purpose:	Obtain reason string for last SSL error
 *
 * Parameters:	none
 *
 * Returns:	SSL error text
 *
 *
 * Authors:	http://developer.postgresql.org/docs/pgsql/src/backend/libpq/be-secure.c
 *
 * Notes:	Some caution is needed here since ERR_reason_error_string will
 *		return NULL if it doesn't recognize the error code.  We don't
 *		want to return NULL ever.
 *
 *              This function submitted as a patch by William Yodlowsky 
 *              <wyodlows@andromeda.rutgers.edu>
 *--
 */
static const char *SSLerrmessage( void )
{
    unsigned long errcode;
    const char *errreason;
    static char errbuf[32];
    
    errcode = ERR_get_error();
    if ( errcode == 0 )
	return "No SSL error reported";

    errreason = (const char *)ERR_reason_error_string( errcode );

    if (errreason != NULL)
	return errreason;

    snprintf(errbuf, sizeof( errbuf ) - 1, "SSL error code %lu", errcode);
    return errbuf;
}

#endif	/* HAVE_LIBSSL */

/*++
 * Function:     atoui
 *
 * Purpose:      Convert a char array to an unsigned int value.
 *
 * Parameters:   const char ptr -- the NULL terminated string to convert
 *               unsigned int ptr -- where the converted value will be stored.
 *
 * Returns:      0 on success
 *               -1 on failure
 *
 * Authors:      Dave McMurtrie <davemcmurtrie@gmail.com>
 *
 * Notes:        Will tolerate trailing plus sign since IMAP rfc allows that as
 *               part of a literal specifier.
 */
extern int atoui( const char *Value, unsigned int *ConvertedValue )
{
    unsigned int Digit;
    
#define MAX_TENTH ( UINT_MAX / 10 )
    
    *ConvertedValue = 0;
    
    while ( *Value >= '0' && *Value <='9') 
    {
	Digit = *Value - '0';
	
	/*
	 * Check for overflow before multiplying.
	 */
	if ( *ConvertedValue > MAX_TENTH )
	{
	    *ConvertedValue = 0;
	    return( -1 );
	}
	*ConvertedValue *= 10;
	
	/*
	 * Check for overflow before adding.
	 */
	if ( Digit > ( UINT_MAX - *ConvertedValue ) )
	{
	    *ConvertedValue = 0;
	    return( -1 );
	}
	*ConvertedValue += Digit;

	Value++;
    }
    
    if ( *Value == '+' )
    {
	if ( *(Value + 1) == '\0' )
	{
	    return( 0 );
	}
	else
	{
	    *ConvertedValue = 0;
	    return( -1 );
	}
    }

    if ( *Value != '\0' )
    {
	*ConvertedValue = 0;
	return( -1 );
    }
    
    return( 0 );
}


/*++
 * Function:	LockMutex
 *
 * Purpose:	lock a mutex
 *
 * Parameters:	ptr to the mutex
 *
 * Returns:	nada -- exits on failure
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
extern void LockMutex( pthread_mutex_t *mutex )
{
    char *fn = "LockMutex()";
    int rc;
    
    rc = pthread_mutex_lock( mutex );
    if ( rc )
    {
	syslog(LOG_ERR, "%s: pthread_mutex_lock() failed [%d]: Exiting.", fn, rc );
	exit( 1 );
    }
    return;
}


/*++
 * Function:	UnLockMutex
 *
 * Purpose:	unlock a mutex
 *
 * Parameters:	ptr to the mutex
 *
 * Returns:	nada -- exits on failure
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
extern void UnLockMutex( pthread_mutex_t *mutex )
{
    char *fn = "UnLockMutex()";
    int rc;
    
    rc = pthread_mutex_unlock( mutex );
    
    if ( rc )
    {
	syslog( LOG_ERR, "%s: pthread_mutex_unlock() failed [%d]: Exiting.", fn, rc );
	exit( 1 );
    }
    return;
}


/*++
 * Function:	Attempt_STARTTLS
 *
 * Purpose:	Upgrade plain text connection/negotiate STARTTLS
 *
 * Parameters:	ptr to an IMAPTransactionDescriptor structure
 *
 * Returns:	0 on success
 *         	-1 on failure
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes: 	This function assumes that SSL support has already
 *       	been initialized.
 * 
 *        	This function is a result of re-factoring of existing
 *       	code resulting from a patch submitted by Martin B.
 *       	Smith <smithmb@ufl.edu>
 *--
 */
#if HAVE_LIBSSL
extern int Attempt_STARTTLS( ITD_Struct *Server )
{
    char *fn = "Attempt_STARTTLS()";

    unsigned int BufLen = BUFSIZE - 1;
    char SendBuf[BUFSIZE];
    char *tokenptr;
    char *endptr;
    char *last;
    int rc;


    syslog( LOG_INFO, "%s: Enabling STARTTLS.", fn );

	snprintf( SendBuf, BufLen, "S0001 STARTTLS\r\n" );
	if ( IMAP_Write( Server->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog(LOG_INFO, "STARTTLS failed: IMAP_Write() failed attempting to send STARTTLS command to IMAP server: %s", strerror( errno ) );
	    goto fail;
	}

	/*
	 * Read the server response
	 */
	if ( ( rc = IMAP_Line_Read( Server ) ) == -1 )
	{
	    syslog(LOG_INFO, "STARTTLS failed: No response from IMAP server after sending STARTTLS command" );
	    goto fail;
	}

	if ( Server->LiteralBytesRemaining )
	{
	    syslog(LOG_ERR, "%s: Unexpected string literal in server response.", fn );
	    goto fail;
	}


	/*
	 * Try to match up the tag in the server response to the client tag.
	 */
	endptr = Server->ReadBuf + rc;

	tokenptr = memtok( Server->ReadBuf, endptr, &last );

	if ( !tokenptr )
	{
	    /*
	     * no tokens found in server response?  Not likely, but we still
	     * have to check.
	     */
	    syslog(LOG_INFO, "STARTTLS failed: server response to STARTTLS command contained no tokens." );
	    goto fail;
	}

	if ( memcmp( (const void *)tokenptr, (const void *)"S0001",
			strlen( tokenptr ) ) )
	{
	    /*
	     * non-matching tag read back from the server... Lord knows what this
	     * is, so we'll fail.
	     */
	    syslog(LOG_INFO, "STARTTLS failed: server response to STARTTLS command contained non-matching tag." );
	    goto fail;
	}

	/*
	 * Now that we've matched the tags up, see if the response was 'OK'
	 */
	tokenptr = memtok( NULL, endptr, &last );

	if ( !tokenptr )
	{
	    /* again, not likely but we still have to check... */
	    syslog(LOG_INFO, "STARTTLS failed: Malformed server response to STARTTLS command" );
	    goto fail;
	}

	if ( memcmp( (const void *)tokenptr, "OK", 2 ) )
	{
	    /*
	     * If the server sent back a "NO" or "BAD", we can look at the actual
	     * server logs to figure out why.  We don't have to break our ass here
	     * putting the string back together just for the sake of logging.
	     */
	    syslog(LOG_INFO, "STARTTLS failed: non-OK server response to STARTTLS command" );
	    goto fail;
	}

	Server->conn->tls = SSL_new( tls_ctx );
	if ( Server->conn->tls == NULL )
	{
	    syslog(LOG_INFO, "STARTTLS failed: SSL_new() failed" );
	    goto fail;
	}

	SSL_clear( Server->conn->tls );
	rc = SSL_set_fd( Server->conn->tls, Server->conn->sd );
	if ( rc == 0 )
	{
	    syslog(LOG_INFO,
		    "STARTTLS failed: SSL_set_fd() failed: %d",
		    SSL_get_error( Server->conn->tls, rc ) );
	    goto fail;
	}

	SSL_set_connect_state( Server->conn->tls );
	rc = SSL_connect( Server->conn->tls );
	if ( rc <= 0 )
	{
	    syslog(LOG_INFO,
		    "STARTTLS failed: SSL_connect() failed, %d: %s",
		    SSL_get_error( Server->conn->tls, rc ), SSLerrmessage() );
	    goto fail;
	}

	return 0;

  fail:
    if ( Server->conn->tls )
    {
	SSL_shutdown( Server->conn->tls );
	SSL_free( Server->conn->tls );
    }
    return -1;
}
#endif


/*++
 * Function:	Get_Server_conn
 *
 * Purpose:	When a client login attempt is made, fetch a usable server
 *              connection descriptor.  This means that either we reuse an
 *              existing ICD, or we open a new one.  Hide that abstraction from
 *              the caller...
 *
 * Parameters:	ptr to username string
 *		ptr to password string
 *              const ptr to client hostname or IP string (for logging only)
 *              ptr to client port string (for logging only)
 *              unsigned char - flag to indicate that the client sent the
 *                              password as a string literal.
 *              ptr to string that will be filled with the server's
 *                            full response (minus tag) to a
 *                            login/authentication request when available.
 *                            NOTE: string must be allocated space at least
 *                            as big as an ITD's ReadBuf (BUFSIZE)
 *
 * Returns:	ICD * on success
 *              NULL on failure
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Credit:      Major SSL additions by Ken Murchison <ken@oceana.com>
 *
 *--
 */
extern ICD_Struct *Get_Server_conn( char *Username, 
				    char *Password,
				    const char *ClientAddr,
				    const char *portstr,
				    unsigned char LiteralPasswd,
				    char *fullResponse )
{
    char *fn = "Get_Server_conn()";
    unsigned int HashIndex;
    ICC_Struct *HashEntry = NULL;
    char SendBuf[BUFSIZE];

    char EncodedAuthBuf[BUFSIZE];
    char AuthBuf[BUFSIZE];
    char AuthBufIndex;

    unsigned int BufLen = BUFSIZE - 1;
    char md5pw[MD5_DIGEST_LENGTH];
    char *tokenptr;
    char *endptr;
    char *last;
    ICC_Struct *ICC_Active;
    ICC_Struct *ICC_tptr;
    ITD_Struct Server;
    int rc;
    unsigned int Expiration;

    EVP_MD_CTX mdctx;
    int md_len;

    Expiration = PC_Struct.cache_expiration_time;
    memset( &Server, 0, sizeof Server );
    
    /* need to md5 the passwd regardless, so do that now */
    EVP_DigestInit(&mdctx, EVP_md5());
    EVP_DigestUpdate(&mdctx, Password, strlen(Password));
    EVP_DigestFinal(&mdctx, md5pw, &md_len);
    
    /* see if we have a reusable connection available */
    ICC_Active = NULL;
    HashIndex = Hash( Username, HASH_TABLE_SIZE );
    
    LockMutex( &mp );
        
    /*
     * Now we just iterate through the linked list at this hash index until
     * we either find the string we're looking for or we find a NULL.
     */
    for ( HashEntry = ICC_HashTable[ HashIndex ]; 
	  HashEntry; 
	  HashEntry = HashEntry->next )
    {
	if ( ( strcmp( Username, HashEntry->username ) == 0 ) &&
	     ( HashEntry->logouttime > 1 ) )
	{
	    ICC_Active = HashEntry;
	    /*
	     * we found this username in our hash table.  Need to know if
	     * the password matches.
	     */
	    if ( memcmp( md5pw, ICC_Active->hashedpw, sizeof md5pw ) )
	    {
		syslog( LOG_NOTICE,
			"%s: Unable to reuse server sd [%d] for user '%s' (%s:%s) because password doesn't match.",
			fn, ICC_Active->server_conn->sd, Username,
			ClientAddr, portstr );
		ICC_Active->logouttime = 1;
	    }
	    else
	    {
		/*
		 * We found a matching password on an inactive server socket.
		 * We can use this guy.  Before we release the mutex, set the
		 * logouttime such that we mark this connection as "active"
		 * again.
		 */
		ICC_Active->logouttime = 0;
	
		/*
		 * The fact that we have this stored in a table as an open
		 * server socket doesn't really mean that it's open.  The
		 * server could've closed it on us.
		 * We need a speedy way to make sure this is still open.
		 * We'll set the fd to non-blocking and try to read from it.
		 * If we get a zero back, the connection is closed.  If we get
		 * EWOULDBLOCK (or some data) we know it's still open.  If we
		 * do read data, make sure we read all the data so we "drain"
		 * any puss that may be left on this socket.
		 */
		fcntl( ICC_Active->server_conn->sd, F_SETFL,
		       fcntl( ICC_Active->server_conn->sd, F_GETFL, 0) | O_NONBLOCK );
		
		while ( ( rc = IMAP_Read( ICC_Active->server_conn, Server.ReadBuf, 
				     sizeof Server.ReadBuf ) ) > 0 );
		
		if ( !rc )
		{
		    syslog( LOG_NOTICE,
			    "%s: Unable to reuse server sd [%d] for user '%s' (%s:%s).  Connection closed by server.",
			    fn, ICC_Active->server_conn->sd, Username,
			    ClientAddr, portstr );
		    ICC_Active->logouttime = 1;
		    continue;
		}
	    
		if ( errno != EWOULDBLOCK )
		{
		    syslog( LOG_NOTICE,
			    "%s: Unable to reuse server sd [%d] for user '%s' (%s:%s). IMAP_read() error: %s",
			    fn, ICC_Active->server_conn->sd, Username, 
			    ClientAddr, portstr, strerror( errno ) );
		    ICC_Active->logouttime = 1;
		    continue;
		}
		
		fcntl( ICC_Active->server_conn->sd, F_SETFL, 
		       fcntl( ICC_Active->server_conn->sd, F_GETFL, 0) & ~O_NONBLOCK );
		
		/* now release the mutex and return the sd to the caller */
		UnLockMutex( &mp );

		/*
		 * We're reusing an existing server socket.  There are a few
		 * counters we have to deal with.
		 */
		IMAPCount->RetainedServerConnections--;
		IMAPCount->InUseServerConnections++;
		IMAPCount->TotalServerConnectionsReused++;
		
		if ( IMAPCount->InUseServerConnections >
		     IMAPCount->PeakInUseServerConnections )
		    IMAPCount->PeakInUseServerConnections = IMAPCount->InUseServerConnections;
	    
		syslog( LOG_INFO,
			"LOGIN: '%s' (%s:%s) on existing sd [%d]",
			Username, ClientAddr, portstr,
			ICC_Active->server_conn->sd );

		/* Set the ICD as 'reused' */
		ICC_Active->server_conn->reused = 1;

		return( ICC_Active->server_conn );
	    }
	}
    }
    
    
    UnLockMutex( &mp );
    
    syslog( LOG_INFO,
	    "LOGIN: '%s' (%s:%s) no previous connection: creating a new one",
	    Username, ClientAddr, portstr);

    /*
     * We don't have an active connection for this user, or the password
     * didn't match.
     * Open a connection to the IMAP server so we can attempt to login 
     */
    Server.conn = ( ICD_Struct * ) malloc( sizeof ( ICD_Struct ) );
    memset( Server.conn, 0, sizeof ( ICD_Struct ) );

    /* As a new connection, the ICD is not 'reused' */
    Server.conn->reused = 0;

    Server.conn->sd = socket( ISD.srv->ai_family, ISD.srv->ai_socktype, 
			      ISD.srv->ai_protocol );
    if ( Server.conn->sd == -1 )
    {
	syslog( LOG_INFO,
		"LOGIN: '%s' (%s:%s) failed: Unable to open server socket: %s",
		Username, ClientAddr, portstr, strerror( errno ) );
	goto fail;
    }

    if ( PC_Struct.send_tcp_keepalives )
    {
	int onoff = 1;
	setsockopt( Server.conn->sd, SOL_SOCKET, SO_KEEPALIVE, &onoff, sizeof onoff );
    }
    
    if ( connect( Server.conn->sd, (struct sockaddr *)ISD.srv->ai_addr, 
		  ISD.srv->ai_addrlen ) == -1 )
    {
	syslog( LOG_INFO,
		"LOGIN: '%s' (%s:%s) failed: Unable to connect to IMAP server: %s",
		Username, ClientAddr, portstr, strerror( errno ) );
	goto fail;
    }
    
    
    /* Read & throw away the banner line from the server */
    
    if ( IMAP_Line_Read( &Server ) == -1 )
    {
	syslog( LOG_INFO,
		"LOGIN: '%s' (%s:%s) failed: No banner line received from IMAP server",
 		Username, ClientAddr, portstr );
	goto fail;
    }

    /*
     * Sanity check.  We don't deal with literal responses in the
     * banner string.
     */
    if ( Server.LiteralBytesRemaining )
    {
	syslog(LOG_ERR, "%s: Unexpected string literal in server banner response.", fn );
	goto fail;
	
    }
    

    /*
     * Do STARTTLS if necessary.
     */
#if HAVE_LIBSSL
    if ( PC_Struct.login_disabled || PC_Struct.force_tls )
    {
	if ( Attempt_STARTTLS( &Server ) != 0 )
	{
	    goto fail;
	}

	/* XXX Should we grab the session id for later reuse? */
    }
#endif /* HAVE_LIBSSL */


    /*
     * Send and validate pre-authentication command if given
     */
    if ( PC_Struct.preauth_command )
    {
	snprintf( SendBuf, BufLen, "P0001 %s\r\n", PC_Struct.preauth_command );
	
	if ( IMAP_Write( Server.conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog( LOG_INFO,
		    "PREAUTH failed: IMAP_Write() failed attempting to send pre-authentication command to IMAP server: %s",
		    strerror( errno ) );
	    goto fail;
	}
    
	// Read the server response
	//
	for ( ;; )
	{
	    if ( ( rc = IMAP_Line_Read( &Server ) ) == -1 )
	    {
		syslog( LOG_INFO,
			"PREAUTH failed: No response from IMAP server after sending pre-authentication command (%s)",
			PC_Struct.preauth_command );
		goto fail;
	    }

	    if ( Server.LiteralBytesRemaining )
	    {
		syslog(LOG_ERR, "%s: Unexpected string literal in server pre-authentication response.", fn );
		goto fail;
	    }
	
	    if ( Server.ReadBuf[0] != '*' )
		break;
	}
    
    
	// Try to match up the tag in the server response to the client tag.
	//
	endptr = Server.ReadBuf + rc;
    
	tokenptr = memtok( Server.ReadBuf, endptr, &last );
    
	if ( !tokenptr )
	{

	    // no tokens found in server response?  Not likely, but we still
	    // have to check.
	    //
	    syslog( LOG_INFO, "PREAUTH failed: server response to pre-authentication command contained no tokens." );
	    goto fail;
	}
    
	if ( memcmp( (const void *)tokenptr, (const void *)"P0001", strlen( tokenptr ) ) )
	{

	    // non-matching tag read back from the server... Lord knows what this
	    // is, so we'll fail.
	    //
	    syslog( LOG_INFO, "PREAUTH failed: server response to pre-authentication command contained non-matching tag." );
	    goto fail;
	}
    
    
	// Now that we've matched the tags up, see if the response was 'OK'
	//
	tokenptr = memtok( NULL, endptr, &last );
    
	if ( !tokenptr )
	{
	    // again, not likely but we still have to check... 
	    //
	    syslog( LOG_INFO, "PREAUTH failed: Malformed server response to pre-authentication command" );
	    goto fail;
	}
    
	if ( memcmp( (const void *)tokenptr, "OK", 2 ) )
	{
	    // In order to log the full server response (minus the tag),
	    // we want to re-construct the ReadBuf starting at the location
	    // currently pointed to by tokenptr.  Thus, we put back the
	    // last space that memtok() had replaced with a null characater
	    // (at location pointed to by last).
	    //
	    *last = ' ';

	    // Then we re-adjust endptr to point to the CR at the end of
	    // the line and set to NULL (a few lines below) so we can use
	    // the rest of the response information as a normal string
	    // 
	    endptr = memchr( last + 1, '\r', endptr - (last + 1) );

	    // No CR is unexpected; does this indicate malformed response?
	    // Probably.  Anyway, we'll just give up on finding any other
	    // info from the server.
	    //
	    if ( !endptr )
	    endptr = last;

	    *endptr = '\0';

	    syslog( LOG_INFO,
		"PREAUTH failed: non-OK server response to pre-authentication command (%s): %s",
		PC_Struct.preauth_command, tokenptr );
	    goto fail;
	}
    }
    

    /*
     * If configured to do so, execute SASL PLAIN authentication
     * using the static authentication username and password from
     * configuration (auth_sasl_plain_username/auth_sasl_plain_password).
     *
     * Note that because this means no password is required from
     * the client, we won't allow this means of authentication
     * without the client sending a shared secret instead, which
     * must match what's in the configuration (auth_shared_secret).
     */
    if ( PC_Struct.auth_sasl_plain_username
	&& PC_Struct.auth_sasl_plain_password
	&& PC_Struct.auth_shared_secret )
    {
	/*
	 * Check shared secret first (accounting for when a password
	 * is wrapped in quotes)
	 */
	if ( *Password == '"' && *(Password + strlen( Password ) - 1) == '"' )
	    rc = strncmp( Password + 1, PC_Struct.auth_shared_secret, strlen( Password ) - 2 );
	else
	    rc = strcmp( Password, PC_Struct.auth_shared_secret );
	if ( rc != 0 )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: shared secret was wrong",
		    Username, ClientAddr, portstr );
	    goto fail;
	}

	/*
	 * Build SASL AUTH PLAIN string:
	 * username\0authentication_username\0authentication_password
	 */
	char *ptr_username;
	unsigned int username_size;

	/*
	 * But first, if username is enclosed in quotes, skip the
	 * first one and overwrite the second with \0 (with pointer
	 * math for our use below, since we are still working on
	 * the original Username)
	 */
	ptr_username = Username;
	username_size = strlen( Username );
	if ( *ptr_username == '"' && *(ptr_username + username_size - 1) == '"' )
	{
	    ++ptr_username;
	    username_size = username_size - 2;
	}

	/*
	 * Add username and \0 to AUTH PLAIN buffer
	 */
	if ( username_size > BufLen - 1 )
	    username_size = BufLen - 1;
	memcpy( AuthBuf, ptr_username, username_size );
	AuthBuf[username_size] = '\0';
	AuthBufIndex = username_size;

	/*
	 * Add authentication username and \0 to AUTH PLAIN buffer
	 */
	AuthBufIndex += snprintf( AuthBuf + AuthBufIndex + 1,
				BufLen - AuthBufIndex - 1,
				"%s",
				PC_Struct.auth_sasl_plain_username );

	/*
	 * Add authentication password to AUTH PLAIN buffer
	 */
	AuthBufIndex += snprintf( AuthBuf + AuthBufIndex + 2,
				BufLen - AuthBufIndex - 2,
				"%s",
				PC_Struct.auth_sasl_plain_password );

	EVP_EncodeBlock( EncodedAuthBuf, AuthBuf, AuthBufIndex + 2 );

	snprintf( SendBuf, BufLen, "A0001 AUTHENTICATE PLAIN %s\r\n", EncodedAuthBuf );

	/* syslog( LOG_INFO, "sending auth plain '%s'", EncodedAuthBuf ); */

	if ( IMAP_Write( Server.conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: IMAP_Write() failed attempting to send AUTHENTICATE command to IMAP server: %s",
		    Username, ClientAddr, portstr, strerror( errno ) );
	    goto fail;
	}
    }


    /*
     * Otherwise, send a normal login command off to the IMAP server.
     *
     * ... but login command has to treat literal passwords differently:
     */
    else if ( LiteralPasswd )
    {
	snprintf( SendBuf, BufLen, "A0001 LOGIN %s {%d}\r\n", 
		  Username, strlen( Password ) );
	if ( IMAP_Write( Server.conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: IMAP_Write() failed attempting to send LOGIN command to IMAP server: %s",
		    Username, ClientAddr, portstr, strerror( errno ) );
	    goto fail;
	}
	
	/*
	 * the server response should be a go ahead
	 */
	if ( ( rc = IMAP_Line_Read( &Server ) ) == -1 )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: Failed to receive go-ahead from IMAP server after sending LOGIN command",
		    Username, ClientAddr, portstr );
	    goto fail;
	}

	if ( Server.LiteralBytesRemaining )
	{
	    syslog(LOG_ERR, "%s: Unexpected string literal in server banner response.  Should be a continuation response.", fn );
	    goto fail;
	    
	}
	
	if ( Server.ReadBuf[0] != '+' )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: bad response from server after sending string literal specifier",
		    Username, ClientAddr, portstr );
	    goto fail;
	}
	
	/* 
	 * now send the password
	 */
	snprintf( SendBuf, BufLen, "%s\r\n", Password );
	
	if ( IMAP_Write( Server.conn, SendBuf, strlen( SendBuf ) ) == -1 )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: IMAP_Write() failed attempting to send literal password to IMAP server: %s",
		    Username, ClientAddr, portstr, strerror( errno ) );
	    goto fail;
	}
    }


    /*
     * Just send the login command via normal means.
     */
    else
    {
	snprintf( SendBuf, BufLen, "A0001 LOGIN %s %s\r\n", 
		  Username, Password );
	
	if ( IMAP_Write( Server.conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: IMAP_Write() failed attempting to send LOGIN command to IMAP server: %s",
		    Username, ClientAddr, portstr, strerror( errno ) );
	    goto fail;
	}
    }
    
	
    /*
     * Read the server response.  From RFC 3501:
     *
     * A server MAY include a CAPABILITY response code in the tagged OK
     * response to a successful LOGIN command in order to send
     * capabilities automatically.  It is unnecessary for a client to
     * send a separate CAPABILITY command if it recognizes these
     * automatic capabilities.
     *
     * We have to be ready for the possibility that this might be an 
     * untagged response...  In an ideal world, we'd want to pass the
     * untagged stuff back to the client.  For now, since the RFC doesn't
     * mandate that behaviour, we're not going to since we don't have a client
     * socket descriptor to send it to.
     */
    for ( ;; )
    {
	if ( ( rc = IMAP_Line_Read( &Server ) ) == -1 )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: No response from IMAP server after sending LOGIN command",
		    Username, ClientAddr, portstr );
	    goto fail;
	}

	if ( Server.LiteralBytesRemaining )
	{
	    syslog(LOG_ERR, "%s: Unexpected string literal in server LOGIN response.", fn );
	    goto fail;
	    
	}
	
	if ( Server.ReadBuf[0] != '*' )
	    break;
    }
    
    
    /*
     * Try to match up the tag in the server response to the client tag.
     */
    endptr = Server.ReadBuf + rc;
    
    tokenptr = memtok( Server.ReadBuf, endptr, &last );
    
    if ( !tokenptr )
    {
	/* 
	 * no tokens found in server response?  Not likely, but we still
	 * have to check.
	 */
	syslog( LOG_INFO,
		"LOGIN: '%s' (%s:%s) failed: server response to LOGIN command contained no tokens.",
		Username, ClientAddr, portstr );
	goto fail;
    }
    
    if ( memcmp( (const void *)tokenptr, (const void *)"A0001", 
		 strlen( tokenptr ) ) )
    {
	/* 
	 * non-matching tag read back from the server... Lord knows what this
	 * is, so we'll fail.
	 */
	syslog( LOG_INFO,
		"LOGIN: '%s' (%s:%s) failed: server response to LOGIN command contained non-matching tag.",
		Username, ClientAddr, portstr );
	goto fail;
    }
    
    
    /*
     * Now that we've matched the tags up, see if the response was 'OK'
     */
    tokenptr = memtok( NULL, endptr, &last );
    
    if ( !tokenptr )
    {
	/* again, not likely but we still have to check... */
	syslog( LOG_INFO,
		"LOGIN: '%s' (%s:%s) failed: Malformed server response to LOGIN command",
		Username, ClientAddr, portstr );
	goto fail;
    }
    
    // In order to give the full server response (minus the tag)
    // back to the caller, we want to re-construct the ReadBuf
    // starting at the location currently pointed to by tokenptr.
    // Thus, we put back the last space that memtok() had replaced
    // with a null characater (at location pointed to by last).
    //
    *last = ' ';

    // Then we re-adjust endptr to point to the CR at the end of
    // the line and set to NULL (a few lines below) so we can use
    // the rest of the response information as a normal string
    // 
    endptr = memchr( last + 1, '\r', endptr - (last + 1) );

    // No CR is unexpected; does this indicate malformed response?
    // Probably.  Anyway, we'll just give up on finding any other
    // info from the server.
    //
    if ( !endptr )
	endptr = last;

    *endptr = '\0';

    // Put the response text into the fullResponse parameter for the caller
    //
    strcpy( fullResponse, tokenptr );

    if ( memcmp( (const void *)tokenptr, "OK", 2 ) )
    {
	syslog( LOG_INFO,
		"LOGIN: '%s' (%s:%s) failed: non-OK server response to LOGIN command: %s",
		Username, ClientAddr, portstr, fullResponse );
	goto fail;
    }
    
    /*
     * put this in our used list and remove it from the free list
     */
    for( ; ; )
    {
	LockMutex( &mp );
	
	if ( ICC_free->next )
	{
	    /* generate the hash index */
	    HashIndex = Hash( Username, HASH_TABLE_SIZE );
	    
	    /* temporarily store the address of the next free structure */
	    ICC_tptr = ICC_free->next;
	    
	    /*
	     * We want to add the newest "used" structure at the front of
	     * the list at the hash index.
	     */
	    ICC_free->next = ICC_HashTable[ HashIndex ];
	    ICC_HashTable[ HashIndex ] = ICC_free;
	    
	    /* 
	     * less typing and more readability, set an "active" pointer.
	     */
	    ICC_Active = ICC_free;
	    
	    /* now point the free listhead to the next available free struct */
	    ICC_free = ICC_tptr;
	    
	    /* fill in the newest used (oxymoron?) structure */
	    strncpy( ICC_Active->username, Username, 
		     sizeof ICC_Active->username );
	    ICC_Active->username[ sizeof ICC_Active->username - 1 ] = '\0';
	    memcpy( ICC_Active->hashedpw, md5pw, sizeof ICC_Active->hashedpw );
	    ICC_Active->logouttime = 0;    /* zero means, "it's active". */
	    ICC_Active->server_conn = Server.conn;
	    
	    Server.conn->ICC = ICC_Active;

	    UnLockMutex( &mp );
	    
	    IMAPCount->InUseServerConnections++;
	    IMAPCount->TotalServerConnectionsCreated++;

	    if ( IMAPCount->InUseServerConnections >
		 IMAPCount->PeakInUseServerConnections )
		IMAPCount->PeakInUseServerConnections = IMAPCount->InUseServerConnections;
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) on new sd [%d]",
		    Username, ClientAddr, portstr, Server.conn->sd );
	    return( Server.conn );
	}
	
	/*
	 * There weren't any free ICC structs.  Try to free one.  Make sure
	 * we unlock the mutex, since ICC_Recycle needs to obtain it.
	 */
	UnLockMutex( &mp );
	
	Expiration = abs( Expiration / 2 );
	
	/*
	 * Eventually, we have to fail
	 */
	if ( Expiration <= 2 )
	{
	    syslog( LOG_INFO,
		    "LOGIN: '%s' (%s:%s) failed: Out of free ICC structs.",
		    Username, ClientAddr, portstr );
	    goto fail;
	}
	
	ICC_Recycle( Expiration );
	
    }
    
  fail:
#if HAVE_LIBSSL
    if ( Server.conn->tls )
    {
	SSL_shutdown( Server.conn->tls );
	SSL_free( Server.conn->tls );
    }
#endif
    close( Server.conn->sd );
    free( Server.conn );
    return( NULL );
}

    



/*++
 * Function:	imparse_isatom
 *
 * Purpose:	determine if a string is an "atom" according to RFC2060
 *		which basically means (if you convolute your way through
 *		the BNF notation in the back of the RFC):  1 or more of
 *		any character except"(" / ")" / "{" / SPACE / CTL / "%" /
 *		"*".
 *
 * Parameters:	const char ptr to the string to examine.
 *
 * Returns:	non-zero if the string is an atom.
 *
 * Authors:	This was taken directly and exactly from cyrus-imap-1.5.14
 *--
 */
extern int imparse_isatom( const char *s )
{
    int len = 0;
    
    if (!*s) return 0;
    for (; *s; s++) 
    {
        len++;
        if (*s & 0x80 || *s < 0x1f || *s == 0x7f ||
            *s == ' ' || *s == '{' || *s == '(' || *s == ')' ||
            *s == '\"' || *s == '%' || *s == '*' || *s == '\\') return 0;
    }
    if (len >= 1024) return 0;
    return 1;
}



/*++
 * Function:	memtok
 *
 * Purpose:	similar to strtok_r, except doesn't require a NULL
 *		terminated string.  Since this is only for IMAP use,
 *              it also doesn't require a "separator" to be passed in,
 *              it assumes a single space will always be the token separator.
 *
 * Parameters:	char ptr.  Beginning of buffer (or NULL)
 *		char ptr.  End of buffer.
 *		ptr to char ptr.  Last position in buffer (for
 *		                  subsequent calls).
 *
 * Returns:	char pointer to the first character of the token.
 *		NULL pointer if no tokens are found.
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
extern char *memtok( char *Begin, char *End, char **Last )
{
    char *CP;
    char *First;

    /*
     * If the Begin address is NULL, pick up one character beyond
     * where we left off.  Check to make sure we didn't leave off at the
     * end of our buffer, though.
     */
    if ( ! Begin )
    {
	if ( *Last == End )
	{
	    return( NULL );
	}
	else
	{
	    First = *Last + 1;
	}
    }
    else
    {
	First = Begin;
    }
    
    if ( ! First )
	return( NULL );

    /* Look for a space */
    CP = memchr( First, ' ', End - First );

    /* 
     * If we don't find a space, maybe we're at the last token in the line.
     * If that's the case, we should be able to find a CR.
     */
    if ( !CP )
	CP = memchr( First, '\r', End - First );
	
    if ( ! CP )
	return( NULL );

    /*
     * If we found the token where we started out, we have a double space, 
     * a /r/r, or a /r at the beginning of the line.  In any case, it's not
     * correct as far as RFC2060 goes.
     */
    if ( CP == First )
	return( NULL );
    
    *Last = CP;
    *CP = '\0';
    
    return( First );
}

	
    
/*++
 * Function:	IMAP_Write
 *
 * Purpose:	Write a buffer to a socket.
 *
 * Parameters:	ptr to a IMAPTransactionDescriptor structure
 *		ptr to buffer
 *		number of bytes in buffer
 * 
 * Returns:	number of bytes written on success
 *		-1 on failure
 *
 * Authors:	Ken Murchison (ken@oceana.com)
 *
 * Notes:	
 *--
 */
extern int IMAP_Write( ICD_Struct *ICD, const void *buf, int count )
{
#if HAVE_LIBSSL
    if ( ICD->tls )
	return SSL_write( ICD->tls, buf, count );
    else
#endif
	return write( ICD->sd, buf, count );
}



/*++
 * Function:	IMAP_Read
 *
 * Purpose:	Read IMAP data from a socket.
 *
 * Parameters:	ptr to a IMAPTransactionDescriptor structure
 *		ptr to buffer
 *		number of bytes to read
 * 
 * Returns:	number of bytes read on success
 *		-1 on failure
 *
 * Authors:	Ken Murchison (ken@oceana.com)
 *
 * Notes:	
 *--
 */
extern int IMAP_Read( ICD_Struct *ICD, void *buf, int count )
{
#if HAVE_LIBSSL
    if ( ICD->tls )
	return SSL_read( ICD->tls, buf, count );
    else
#endif
	return read( ICD->sd, buf, count );
}



/*++
 * Function:	IMAP_Literal_Read
 *
 * Purpose:	Read IMAP string literals from a socket.
 *
 * Parameters:	ptr to a IMAPTransactionDescriptor structure
 * 
 * Returns:	number of bytes read on success
 *		-1 on failure
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:	
 *--
 */
extern int IMAP_Literal_Read( ITD_Struct *ITD )
{
    char *fn = "IMAP_Literal_Read()";
    int Status;
    unsigned int i, j;
    struct pollfd fds[2];
    nfds_t nfds;
    int pollstatus;

    /*
     * If there aren't any LiteralBytesRemaining, just return 0.
     */
    if ( ! ITD->LiteralBytesRemaining )
	return( 0 );

    
    /* scoot the buffer */
    for ( i = ITD->ReadBytesProcessed, j = 0; 
	  i <= ITD->BytesInReadBuffer; 
	  i++, j++ )
    {
	ITD->ReadBuf[j] = ITD->ReadBuf[i];
    }
    ITD->BytesInReadBuffer -= ITD->ReadBytesProcessed;
    ITD->ReadBytesProcessed = 0;

    /*
     * If we have any data in our buffer, return what we have.
     */
    if ( ITD->BytesInReadBuffer > 0 )
    {
	if ( ITD->BytesInReadBuffer >= ITD->LiteralBytesRemaining )
	{
	    ITD->ReadBytesProcessed = ITD->LiteralBytesRemaining;
	    ITD->LiteralBytesRemaining = 0;
	    return( ITD->ReadBytesProcessed );
	}
	else
	{
	    ITD->ReadBytesProcessed += ITD->BytesInReadBuffer;
	    ITD->LiteralBytesRemaining -= ITD->BytesInReadBuffer;
	    return( ITD->ReadBytesProcessed );
	}
    }
	
    /*
     * No data left in the buffer.  Have to call read.  Read either
     * the number of literal bytes left, or the rest of our buffer --
     * whichever is smaller.
     *
     */    
    nfds = 1;
    fds[0].fd = ITD->conn->sd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    
    pollstatus = poll( fds, nfds, POLL_TIMEOUT );
    if ( !pollstatus )
    {
	syslog( LOG_ERR, "%s: poll() for data on sd [%d] timed out.", fn, ITD->conn->sd );
	return( -1 );
    }
    if ( pollstatus < 0 )
    {
	syslog( LOG_ERR, "%s: poll() for data on sd [%d] failed: %s.", fn, ITD->conn->sd, strerror( errno ) );
	return( -1 );
    }
    if ( !( fds[0].revents & POLLIN ) )
    {
	syslog( LOG_ERR, "%s: poll() for data on sd [%d] returned nothing.", fn, ITD->conn->sd );
	return( -1 );
    }    
    
    Status = IMAP_Read(ITD->conn, &ITD->ReadBuf[ITD->BytesInReadBuffer],
		  (sizeof ITD->ReadBuf - ITD->BytesInReadBuffer ) );
    
    
    if ( Status == 0 )
    {
	syslog(LOG_WARNING, "%s: connection closed prematurely.", fn);
	return(-1);
    }
    else if ( Status == -1 )
    {
	syslog(LOG_ERR, "%s: IMAP_Read() failed: %s", fn, strerror(errno) );
	return(-1);
    }
    
    /*
     * update the bytes remaining and return the byte count read.
     */
    ITD->BytesInReadBuffer += Status;
    
    if ( ITD->BytesInReadBuffer >= ITD->LiteralBytesRemaining )
    {
	ITD->ReadBytesProcessed = ITD->LiteralBytesRemaining;
	ITD->LiteralBytesRemaining = 0;
	return( ITD->ReadBytesProcessed );
    }
    else
    {
	ITD->ReadBytesProcessed += ITD->BytesInReadBuffer;
	ITD->LiteralBytesRemaining -= ITD->BytesInReadBuffer;
	return( ITD->ReadBytesProcessed );
    }
}





/*++
 * Function:	IMAP_Line_Read
 *
 * Purpose:	Line-oriented buffered reads from the IMAP server
 *
 * Parameters:	ptr to a IMAPTransactionDescriptor structure
 *
 * Returns:	Number of bytes on success
 *              -1 on error
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:	caller must be certain that the IMAPTransactionDescriptor
 *		is initialized to zero on the first call.
 *
 *--
 */
extern int IMAP_Line_Read( ITD_Struct *ITD )
{
    char *CP;
    int Status;
    unsigned int i, j;
    int rc;
    char *fn = "IMAP_Line_Read()";
    char *EndOfBuffer;

    /*
     * Sanity check.  This function should never be called if there are
     * literal bytes remaining to be processed.
     */
    if ( ITD->LiteralBytesRemaining )
    {
      syslog(LOG_ERR, "%s: Sanity check failed! Literal bytestream has not been fully processed (%d bytes remain) and line-oriented read function was called again.", fn, ITD->LiteralBytesRemaining );
      /*
       * Previous behavior was to exit, but that was wrong.  This sanity
       * check only affects a single connection and should not kill the entire
       * process.
       * Just return failure and let the caller deal with it.
       */
      return( -1 );
    }
    

    /* Point End to the end of our buffer */
    EndOfBuffer = &ITD->ReadBuf[sizeof ITD->ReadBuf - 1];


    /* 
     * Shift the contents of our buffer.  This will erase any previous
     * line that we already gave to a caller.
     */
    for ( i = ITD->ReadBytesProcessed, j = 0; 
	  i <= ITD->BytesInReadBuffer; 
	  i++, j++ )
    {
	ITD->ReadBuf[j] = ITD->ReadBuf[i];
    }
    ITD->BytesInReadBuffer -= ITD->ReadBytesProcessed;
    ITD->ReadBytesProcessed = 0;

    for (;;)
    {
	/*
	 * If we've been called before, we may already have another line
	 * in the buffer that we can return to the caller.
	 */
	CP = (char *)memchr( ITD->ReadBuf, '\n', ITD->BytesInReadBuffer );
	
	if ( CP )
	{
	    /*
	     * found a '\n'.  Check to see if it's preceded by a '\r'
	     * but make sure we catch the case where '\n' is the first
	     * character sent.  If we find this, it could be the result
	     * of a "more data" scenerio.
	     */
	    if ( CP != ITD->ReadBuf )
	    {
		/* reset the moredata flag */
		ITD->MoreData = 0;

		if ( *(CP - 1) == '\r' )
		{
		    /*
		     * Set ReadBytesProcessed to the length of the line
		     * we just found.  Just subtract the address of the
		     * beginning of the buffer from the address of our
		     * "/n" in the buffer.  Always need to add one.
		     */
		    ITD->ReadBytesProcessed = ( CP - ITD->ReadBuf + 1);
		    
		    /*
		     * As if this isn't already ugly enough, now we have
		     * to check whether this is a line that indicates a
		     * string literal is coming next.  How do we know?
		     * If it is, the line will end with {bytecount}.
		     */
		    if ( ((CP - ITD->ReadBuf + 1) > 2 ) && ( *(CP - 2) == '}' ))
		    {
			char *LiteralEnd;
			char *LiteralStart;
			
			LiteralStart = NULL;
			
			/*
			 * Found a '}' as the last character on the line.
			 * Save it's place and then look for the
			 * beginning '{'.
			 */
			LiteralEnd = CP - 2;
			CP -= 2;
			
			for ( ; CP >= ITD->ReadBuf; CP-- )
			{
			    if ( *CP == '{' )
			    {
				LiteralStart = CP;
				break;
			    }
			}
			
			if ( LiteralStart )
			{
			    /*
			     * We found an opening and closing { } pair.  The
			     * thing in between should be a number specifying
			     * a byte count.  That would be as much as we needed
			     * to know if it wasn't for the fact that RFC 2088
			     * allows for a + sign in the literal specification
			     * that has a different meaning when a client is
			     * sending a literal to a server.
			     */
			    if ( *(LiteralEnd - 1) == '+' )
			    {
				ITD->NonSyncLiteral = 1;
			    }
			    else if ( *(LiteralEnd - 1) == '{' )
			    {
				/*
				 * This is a {}.  No clue why any client
				 * would ever send this, but just pretend
				 * we never saw it.
				 */
				return( ITD->ReadBytesProcessed );
			    }
			    else
			    {
				ITD->NonSyncLiteral = 0;
			    }
			

			    /* To grab the number, bump our
			     * starting char pointer forward a byte and temporarily
			     * turn the closing '}' into a NULL.  Don't worry about
			     * the potential '+' sign, atoui won't care.
			     */
			    LiteralStart++;
			    *LiteralEnd = '\0';

			    rc = atoui( LiteralStart, &ITD->LiteralBytesRemaining );
			    
			    if ( rc == -1 )
			    {
				syslog(LOG_WARNING, "%s: atoui() failed on string '%s'", fn, LiteralStart );
				*LiteralEnd = '}';
				return(0);
			    }
			    
			    *LiteralEnd = '}';
			}
		    }
		    
		    
		    /*
		     * This looks redundant, huh?
		     */
		    return( ITD->ReadBytesProcessed );
		}
		else
		{
		    /*
		     * found a '\n' that's not preceded by a '\r'.
		     */
		    syslog(LOG_WARNING, "%s: Protocol error.  Line terminated by LF, not CRLF", fn);
		    return(-1);
		}
	    }
	    else
	    {
		/*
		 * We just processed a line that has '\n' as the first
		 * character.  This may or may not be a problem.
		 */
		if ( ITD->MoreData )
		{
		    /*
		     * When we set the MoreData flag, we return 20 bytes fewer
		     * than what's in our buffer.  It's possible for that
		     * to send the CR but not the LF back to the caller,
		     * leaving it as the first thing in the buffer now.
		     * we can't be sure that this is the case, but the client
		     * and the server can fight it out if it's not.
		     */
		    ITD->ReadBytesProcessed = 1;
		    return( ITD->ReadBytesProcessed );
		}
		
		else
		{
		    syslog(LOG_WARNING, "%s: Protocol error.  Line begins with LF.", fn);
		    return(-1);
		}
		
	    }
	}
	
	/* 
	 * There weren't any "lines" in our buffer.  We need to get more data
	 * from the server.  Ultimately, we'll want to call IMAP_Read and
	 * add on to the end of the existing buffer.  
	 *
	 * Before we go off and wildly start calling IMAP_Read() we should
	 * really make sure that we have space left in our buffer.  If not,
	 * set the "more to come" flag and return what we have to the caller.
	 */
	if ( ( sizeof ITD->ReadBuf - ITD->BytesInReadBuffer ) < 1 )
	{
	    /*
	     * less than one byte of storage left in our buffer.  Return what
	     * we have, but get a little bit tricky -- don't return everything
	     * that we have.  The reason for this is because the last thing
	     * in our buffer right now could just happen to be {80 (the
	     * beginning of a string literal specifier).  If we just return
	     * this and come back to start reading more, we'll completely miss
	     * the fact that a literal is coming next.  If we return all but 20
	     * bytes of the current buffer, we completely negate that potential
	     * problem.
	     */
	    ITD->MoreData = 1;
	    CP = EndOfBuffer - 20;
	    
	    /*
	     * Set ReadBytesProcessed to the length of the line
	     * we're gonna return.
	     */
	    ITD->ReadBytesProcessed = ( CP - ITD->ReadBuf + 1);
	    return( ITD->ReadBytesProcessed );
	}
	
	Status = IMAP_Read(ITD->conn, &ITD->ReadBuf[ITD->BytesInReadBuffer],
		      (sizeof ITD->ReadBuf - ITD->BytesInReadBuffer ) );
	
	if ( Status == 0 )
	{
	    syslog(LOG_WARNING, "%s: connection closed prematurely.", fn);
	    return(-1);
	}
	else if ( Status == -1 )
	{
	    syslog(LOG_ERR, "%s: IMAP_Read() failed: %s", fn, strerror(errno) );
	    return(-1);
	}
		
	/*
	 * update the buffer count and head back to the top of the
	 * for loop.
	 */
	ITD->BytesInReadBuffer += Status;
    }
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

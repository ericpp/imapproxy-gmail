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
**	request.c
**
**  Abstract:
**
**	Routines to handle IMAP client requests...  Specifically, this module
**	contains the handler thread (Handle_Request) that takes care of
**	incoming client connections.  It also contains one function for each
**	of the 5 unauthenticated commands that the proxy server can handle
**	without having to make a connection to the real IMAP server.  Finally,
**	the raw proxy function resides in this module, as well.
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
**	Revision 1.25  2009/10/16 14:12:55  dave64
**	applied patch by Jose Luis Tallon to fix compiler warnings
**
**	Revision 1.24  2008/10/20 13:48:55  dave64
**	Fixed buffer overflow condition when doing AUTH LOGIN.
**	Applied patch by Michael M. Slusarz to make internal
**	commands RFC compliant (prepend with X instead of P_).
**	Added support for XPROXYREUSE response.
**
**	Revision 1.23  2007/05/31 12:11:24  dave64
**	Applied ipv6 patch by Antonio Querubin.
**
**	Revision 1.22  2006/02/16 18:38:36  dave64
**	Patch to add internal version command by Matt Selsky.
**
**	Revision 1.21  2005/07/06 11:53:19  dgm
**	Added support for enable_admin_commands config option.
**
**	Revision 1.20  2005/06/15 12:07:12  dgm
**	Remove unused variables.  Fixed snprintf argument lists.
**	Include missing config.h directive.
**
**	Revision 1.19  2004/11/10 15:33:04  dgm
**	Explictly NULL terminate all strings that are the result
**	of strncpy.  Also enforce checking of LiteralBytesRemaining
**	after any call to IMAP_Line_Read.
**
**	Revision 1.18  2004/02/24 15:19:06  dgm
**	Added support for SELECT caching.
**
**	Revision 1.17  2003/10/09 14:11:13  dgm
**	bugfix: set TotalClientLogins to zero in cmd_resetcounters, submitted
**	by Geoffrey Hort <g.hort@unsw.edu.au>.  Changes to allow syslogging of the
**	client source port.  Added timestamps to protocol log entries.
**
**	Revision 1.16  2003/07/14 16:26:02  dgm
**	Removed erroneous newline from syslog() call to prevent compiler
**	warning.
**
**	Revision 1.15  2003/07/07 13:31:09  dgm
**	Bugfix by Gary Windham <windhamg@email.arizona.edu>.  Raw_Proxy() loop
**	was not dealing with string literals correctly when the server
**	responded with something other than a '+'.
**
**	Revision 1.14  2003/05/20 19:11:25  dgm
**	Comment changes only.
**
**	Revision 1.13  2003/05/15 11:35:39  dgm
**	Patch by Ken Murchison <ken@oceana.com> to clean up build process:
**	conditionally include sys/param.h instead of defining MAXPATHLEN.
**
**	Revision 1.12  2003/05/13 11:41:26  dgm
**	Patches by Ken Murchison <ken@oceana.com> to clean up build process.
**
**	Revision 1.11  2003/05/08 17:20:43  dgm
**	Added code to send untagged server responses back to clients
**	on LOGOUT.
**
**	Revision 1.10  2003/05/06 12:11:47  dgm
**	Applied patches by Ken Murchison <ken@oceana.com> to include SSL
**	support.
**
**	Revision 1.9  2003/02/20 12:57:26  dgm
**	Raw_Proxy() sends UNSELECT instead of CLOSE if the server supports it.
**
**	Revision 1.8  2003/02/19 12:57:15  dgm
**	Added support for "AUTHENTICATE LOGIN".
**
**	Revision 1.7  2003/02/14 18:25:40  dgm
**	Fixed bug in cmd_newlog.  ftruncate doesn't reset file pointer so
**	I added an lseek.
**
**	Revision 1.6  2003/01/22 13:03:25  dgm
**	Changes to HandleRequest() and cmd_login() to support clients that
**	send the password as a literal string on login.
**
**	Revision 1.5  2002/08/30 13:24:43  dgm
**	Added support for total client logins counter
**
**	Revision 1.4  2002/08/28 15:59:25  dgm
**	replaced all internal log function calls with standard syslog calls.
**	Added P_RESETCOUNTERS command.
**	Added logic to time out connections in the raw proxy loop.
**
**	Revision 1.3  2002/08/27 20:15:16  dgm
**	No longer bother doing a dns lookup before calling Get_Server_sd().
**	We'll only pass the ip address string instead of possibly hostname.
**
**	Revision 1.2  2002/07/18 20:43:17  dgm
**	added p_dumpicc and p_newlog commands.  Changed trace
**	command to p_trace.
**
**	Revision 1.1  2002/07/03 12:08:34  dgm
**	Initial revision
**
*/


#define _REENTRANT

#include <config.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <poll.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <openssl/evp.h>

#include "common.h"
#include "imapproxy.h"

/*
 * There are a few global variables that we care about.  Make sure we know
 * about them here.
 */
extern char Banner[BUFSIZE];
extern int BannerLen;
extern char Capability[BUFSIZE];
extern int CapabilityLen;
extern IMAPCounter_Struct *IMAPCount;
extern ISD_Struct ISD;
extern pthread_mutex_t mp;
extern pthread_mutex_t trace;
extern char TraceUser[MAXUSERNAMELEN];
extern int Tracefd;
extern ICC_Struct *ICC_HashTable[ HASH_TABLE_SIZE ];
extern ProxyConfig_Struct PC_Struct;

/*
 * Function prototypes for internal entry points.
 */
static int cmd_noop( ITD_Struct *, char * );
static int cmd_logout( ITD_Struct *, char * );
static int cmd_capability( ITD_Struct *, char * );
static int cmd_authenticate_login( ITD_Struct *, char * );
static int cmd_login( ITD_Struct *, char *, char *, int, char *, unsigned char );
static int cmd_trace( ITD_Struct *, char *, char * );
static int cmd_dumpicc( ITD_Struct *, char * );
static int cmd_newlog( ITD_Struct *, char * );
static int cmd_resetcounters( ITD_Struct *, char * );
static int cmd_version( ITD_Struct *, char * );
static int Raw_Proxy( ITD_Struct *, ITD_Struct *, ISC_Struct * );



/*
 * Function definitions.
 */

/*++
 * Function:	cmd_newlog
 *
 * Purpose:	Clear the proxy trace log file.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *              char ptr to Tag sent with this command.
 *
 * Returns:	0 on success
 *		-1 on failure
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
static int cmd_newlog( ITD_Struct *itd, char *Tag )
{
    char *fn = "cmd_newlog";
    char SendBuf[BUFSIZE];
    unsigned int BufLen = BUFSIZE - 1;
    int rc;
    
    SendBuf[BUFSIZE - 1] = '\0';
    
    if ( ! PC_Struct.enable_admin_commands )
    {
	snprintf( SendBuf, BufLen, "%s BAD Unrecognized command\r\n", Tag );
	if ( IMAP_Write( itd->conn, SendBuf, strlen( SendBuf ) ) == -1 )
	{
	    syslog( LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror( errno ) );
	    return( -1 );
	}
	return( 0 );
    }
    

    rc = ftruncate( Tracefd, 0 );
    
    if ( rc != 0 )
    {
	syslog(LOG_ERR, "%s: ftruncate() failed: %s", fn, strerror( errno ) );
	snprintf( SendBuf, BufLen, "%s NO internal server error\r\n", Tag );

	if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	    return( -1 );
	}
	
	return( -1 );
    }
    
    /*
     * bugfix.  ftruncate doesn't reset the file pointer...
     */
    rc = lseek( Tracefd, 0, SEEK_SET );
    
    if ( rc < 0 )
    {
	syslog(LOG_ERR, "%s: lseek() failed: %s", fn, strerror( errno ) );
	snprintf( SendBuf, BufLen, "%s NO internal server error\r\n", Tag );
	
	if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	    return( -1 );
	}
	
	return( -1 );
    }

    snprintf( SendBuf, BufLen, "%s OK Logfile cleared\r\n", Tag );
    
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	return( -1 );
    }
    
    return( 0 );
}


/*++
 * Function:	cmd_resetcounters
 *
 * Purpose:	Reset the global high-water marks and total counters.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *		char ptr to Tag sent with this command.
 *
 * Returns:	0 on success.
 *		-1 on failure.
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:	Always key to remember that we don't take out a mutex
 *		anywhere that we update these global counters.  There's
 *		never a guarantee that they'll be exactly correct but
 *		for the performance penalty we'd pay to make them correct
 *		we just don't care.
 *--
 */
static int cmd_resetcounters( ITD_Struct *itd, char *Tag )
{
    char *fn = "cmd_resetcounters";
    char SendBuf[BUFSIZE];
    unsigned int BufLen = BUFSIZE -1;
    
    SendBuf[BufLen] = '\0';

    if ( ! PC_Struct.enable_admin_commands )
    {
	snprintf( SendBuf, BufLen, "%s BAD Unrecognized command\r\n", Tag );
	if ( IMAP_Write( itd->conn, SendBuf, strlen( SendBuf ) ) == -1 )
	{
	    syslog( LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror( errno ) );
	    return( -1 );
	}
	return( 0 );
    }
    
    /*
     * Bugfix by Geoffrey Hort <g.hort@unsw.edu.au> -- I forgot to zero
     * out TotalClientLogins...
     */
    IMAPCount->CountTime = time( 0 );
    IMAPCount->PeakClientConnections = 0;
    IMAPCount->PeakInUseServerConnections = 0;
    IMAPCount->PeakRetainedServerConnections = 0;
    IMAPCount->TotalClientConnectionsAccepted = 0;
    IMAPCount->TotalServerConnectionsCreated = 0;
    IMAPCount->TotalServerConnectionsReused = 0;
    IMAPCount->TotalClientLogins = 0;
    
    snprintf( SendBuf, BufLen, "%s OK Counters reset\r\n", Tag );
    
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	return( -1 );
    }
    
    return( 0 );
}



/*++
 * Function:	cmd_dumpicc
 *
 * Purpose:	Dump the contents of all IMAP connection context structs.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *              char ptr to Tag sent with this command.
 *
 * Returns:	0 on success
 *		-1 on failure
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
static int cmd_dumpicc( ITD_Struct *itd, char *Tag )
{
    char *fn = "cmd_dumpicc";
    char SendBuf[BUFSIZE];
    unsigned int HashIndex;
    ICC_Struct *HashEntry;
    unsigned int BufLen = BUFSIZE - 1;
    
    SendBuf[BUFSIZE - 1] = '\0';

    if ( ! PC_Struct.enable_admin_commands )
    {
	snprintf( SendBuf, BufLen, "%s BAD Unrecognized command\r\n", Tag );
	if ( IMAP_Write( itd->conn, SendBuf, strlen( SendBuf ) ) == -1 )
	{
	    syslog( LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror( errno ) );
	    return( -1 );
	}
	return( 0 );
    }
    
    LockMutex( &mp );
    
    for ( HashIndex = 0; HashIndex < HASH_TABLE_SIZE; HashIndex++ )
    {
	HashEntry = ICC_HashTable[ HashIndex ];
	
	while ( HashEntry )
	{
	    snprintf( SendBuf, BufLen, "* XPROXY_DUMPICC %d %s %s\r\n", HashEntry->server_conn->sd,
		      HashEntry->username,
		      ( ( HashEntry->logouttime ) ? "Cached" : "Active" ) );
	    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
	    {
		UnLockMutex( &mp );
		syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
		return( -1 );
	    }
	    HashEntry = HashEntry->next;
	}
    }
    
    UnLockMutex( &mp );
    
    snprintf( SendBuf, BufLen, "%s OK Completed\r\n", Tag );
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	return( -1 );
    }
    
    return( 0 );
}



/*++
 * Function:	cmd_version
 *
 * Purpose:	Show the IMAP Proxy version string.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *              char ptr to Tag sent with this command.
 *
 * Returns:	0 on success
 *		-1 on failure
 *
 * Authors:     Matt Selsky <selsky@columbia.edu>
 *--
 */
static int cmd_version( ITD_Struct *itd, char *Tag )
{
    char *fn = "cmd_version";
    char SendBuf[BUFSIZE];
    unsigned int BufLen = BUFSIZE - 1;
    
    SendBuf[BUFSIZE - 1] = '\0';

    if ( ! PC_Struct.enable_admin_commands )
    {
	snprintf( SendBuf, BufLen, "%s BAD Unrecognized command\r\n", Tag );
	if ( IMAP_Write( itd->conn, SendBuf, strlen( SendBuf ) ) == -1 )
	{
	    syslog( LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror( errno ) );
	    return( -1 );
	}
	return( 0 );
    }

    snprintf( SendBuf, BufLen, "* XPROXY_VERSION %s\r\n", IMAP_PROXY_VERSION );
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	return( -1 );
    }

    snprintf( SendBuf, BufLen, "%s OK Completed\r\n", Tag );
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	return( -1 );
    }

    return( 0 );
}



/*++
 * Function:	cmd_trace
 *
 * Purpose:	turn on per-user tracing in the proxy server.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *              char ptr to Tag sent with this command.
 *              char ptr to the username we want to trace (NULL to turn
 *              off tracing)
 *
 * Returns:	0 on success
 *		-1 on failure
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
static int cmd_trace( ITD_Struct *itd, char *Tag, char *Username )
{
    char *fn = "cmd_trace";
    char SendBuf[BUFSIZE];
    unsigned int BufLen = BUFSIZE - 1;
    
    SendBuf[BUFSIZE - 1] = '\0';

    if ( ! PC_Struct.enable_admin_commands )
    {
	snprintf( SendBuf, BufLen, "%s BAD Unrecognized command\r\n", Tag );
	if ( IMAP_Write( itd->conn, SendBuf, strlen( SendBuf ) ) == -1 )
	{
	    syslog( LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror( errno ) );
	    return( -1 );
	}
	return( 0 );
    }
    
    /*
     * Here are the tracing semantics:
     *
     * Tracing is to be limited to only one user at a time.  This decision was
     * made for a few different reasons.  First, to conserve system resources
     * such as disk space.  Second, to improve overall server performance --
     * tracing will slow a thread down.  Third, so a sysadmin doesn't forget
     * that tracing is turned on for a user (like I commonly do when I enable
     * tracing in cyrus imapd).  Fourth, it's just easier this way.
     */    
    
    LockMutex( &trace );
    
    if ( !Username )
    {
	snprintf( SendBuf, BufLen, "\n\n-----> C= %d %s PROXY: user tracing disabled. Expect further output until client logout.\n", (int)time(0), TraceUser );
	write( Tracefd, SendBuf, strlen( SendBuf ) );
	
	memset( TraceUser, 0, sizeof TraceUser );
	snprintf( SendBuf, BufLen, "%s OK Tracing disabled\r\n", Tag );
	if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	    UnLockMutex( &trace );
	    return( -1 );
	}

	UnLockMutex( &trace );
	return( 0 );
    }

    if ( TraceUser[0] )
    {
	/* guarantee no runaway strings */
	TraceUser[sizeof TraceUser - 1] = '\0';
	snprintf( SendBuf, BufLen, "%s BAD Tracing already enabled for user %s\r\n", Tag, TraceUser );
	if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	    UnLockMutex( &trace );
	    return( -1 );
	}
	
	UnLockMutex( &trace );
	return( 0 );
	
    }
    
    strncpy( TraceUser, Username, sizeof TraceUser - 1 );
    TraceUser[ sizeof TraceUser - 1 ] = '\0';
    
    snprintf( SendBuf, BufLen, "%s OK Tracing enabled for user %s.\r\n",
		    Tag, TraceUser );
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	UnLockMutex( &trace );
	return( -1 );
    }

    snprintf( SendBuf, BufLen, "\n\n-----> C= %d %s PROXY: user tracing enabled.\n", (int)time(0), TraceUser );
    write( Tracefd, SendBuf, strlen( SendBuf ) );
    
    UnLockMutex( &trace );
    return( 0 );
}



/*++
 * Function:	cmd_noop
 *
 * Purpose:	implement the NOOP IMAP command.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *
 * Returns:	0 on success
 *		-1 on failure
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
static int cmd_noop( ITD_Struct *itd, char *Tag )
{
    char *fn = "cmd_noop";
    char SendBuf[BUFSIZE];
    unsigned int BufLen = BUFSIZE - 1;
    
    SendBuf[BUFSIZE - 1] = '\0';
    
    snprintf( SendBuf, BufLen, "%s OK Completed\r\n", Tag );
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	return( -1 );
    }
    
    return( 0 );
}



/*++
 * Function:	cmd_logout
 *
 * Purpose:	implement the LOGOUT IMAP command.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *
 * Returns:	0 on success
 *		-1 on failure
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
static int cmd_logout( ITD_Struct *itd, char *Tag )
{
    char *fn = "cmd_logout";
    char SendBuf[BUFSIZE];
    unsigned int BufLen = BUFSIZE - 1;
    
    SendBuf[BUFSIZE - 1] = '\0';
    
    snprintf( SendBuf, BufLen, "* BYE LOGOUT received\r\n%s OK Completed\r\n",
	      Tag );
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() to client failed on sd [%d]: %s", fn, itd->conn->sd, strerror(errno) );
	return( -1 );
    }
    
    return( 0 );
}



/*++
 * Function:	cmd_capability
 *
 * Purpose:	implement the CAPABILITY IMAP command.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *
 * Returns:	0 on success
 *		-1 on failure
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
static int cmd_capability( ITD_Struct *itd, char *Tag )
{
    char *fn = "cmd_capability";
    char SendBuf[BUFSIZE];
    unsigned int BufLen = BUFSIZE - 1;
    
    SendBuf[BUFSIZE - 1] = '\0';
    
    snprintf( SendBuf, BufLen, "%s%s OK Completed\r\n",Capability, Tag );
    if ( IMAP_Write( itd->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	return( -1 );
    }
    
    return( 0 );
}


/*++
 * Function:	cmd_authenticate_login
 *
 * Purpose:	implement the AUTHENTICATE LOGIN mechanism
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *              ptr to client tag
 *
 * Returns:	0 on success prior to authentication
 *              1 on success after authentication (we caught a logout)
 *              -1 on failure	
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
static int cmd_authenticate_login( ITD_Struct *Client,
				   char *Tag )
{
    char *fn = "cmd_authenticate_login()";
    char SendBuf[BUFSIZE];
    char Username[MAXUSERNAMELEN];
    char EncodedUsername[BUFSIZE];
    char Password[MAXPASSWDLEN];
    char EncodedPassword[BUFSIZE];
    ICD_Struct *conn;
    int rc;
    ITD_Struct Server;
    char fullServerResponse[BUFSIZE] = "\0\0\0";
    int BytesRead;
    struct sockaddr_storage cli_addr;
    int sockaddrlen;
    char hostaddr[INET6_ADDRSTRLEN], portstr[NI_MAXSERV];
    
    unsigned int BufLen = BUFSIZE - 1;
    memset ( &Server, 0, sizeof Server );
    sockaddrlen = sizeof( struct sockaddr_storage );
    
    /*
     * send a base64 encoded username prompt to the client.  Note that we're
     * using our Username and EncodedUsername buffers temporarily here to
     * avoid allocating additional buffers.  Keep this in mind for future
     * code modification...
     */
    snprintf( Username, MAXUSERNAMELEN - 1, "Username:" );
    
    EVP_EncodeBlock( EncodedUsername, Username, strlen( Username ) );
    
    snprintf( SendBuf, BufLen, "+ %s\r\n", EncodedUsername );
    
    if ( IMAP_Write( Client->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	syslog(LOG_ERR, "%s: Unable to send base64 encoded username prompt to client: %s", fn, strerror(errno) );
	return( -1 );
    }

    /*
     * The response from the client should be a base64 encoded version of the
     * username.
     */
    BytesRead = IMAP_Line_Read( Client );
    
    if ( BytesRead == -1 )
    {
	syslog( LOG_NOTICE, "%s: Failed to read base64 encoded username from client on socket %d", fn, Client->conn->sd );
	return( -1 );
    }

    /*
     * Don't accept literals from the client here.
     */
    if ( Client->LiteralBytesRemaining )
    {
	syslog( LOG_NOTICE, "%s: Read unexpected literal specifier from client on socket %d", fn, Client->conn->sd );
	return( -1 );
    }
    
    /*
     * Easy, but not perfect sanity check.  If the client sent enough data
     * to fill our entire buffer, we're not even going to bother looking at it.
     */
    if ( ( Client->MoreData ) ||
	 ( BytesRead > BufLen ) ||
	 ( BytesRead > MAXUSERNAMELEN - 1 ) )
    {
	syslog( LOG_NOTICE, "%s: Base64 encoded username sent from client on sd %d is too large.", fn, Client->conn->sd );
	return( -1 );
    }

    /*
     * copy BytesRead -2 so we don't include the CRLF.
     */
    memcpy( (void *)EncodedUsername, (const void *)Client->ReadBuf, 
	    BytesRead - 2 );
    
    rc = EVP_DecodeBlock( Username, EncodedUsername, BytesRead - 2 );
    Username[rc] = '\0';
    
    /*
     * Same drill all over again, except this time it's for the password.
     */
    snprintf( Password, MAXPASSWDLEN - 1, "Password:" );
    
    EVP_EncodeBlock( EncodedPassword, Password, strlen( Password ) );
    
    snprintf( SendBuf, BufLen, "+ %s\r\n", EncodedPassword );
    
    if ( IMAP_Write( Client->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
        syslog(LOG_ERR, "%s: Unable to send base64 encoded password prompt to client: %s", fn, strerror(errno) );
        return( -1 );
    }

    BytesRead = IMAP_Line_Read( Client );

    if ( Client->LiteralBytesRemaining )
    {
	syslog( LOG_ERR, "%s: received unexpected literal specifier from client on socket %d", fn, Client->conn->sd );
	return( -1 );
    }
    
    if ( BytesRead == -1 )
    {
        syslog( LOG_NOTICE, "%s: Failed to read base64 encoded password from client on socket %d", fn, Client->conn->sd );
	return( -1 );
    }
    
    if ( ( Client->MoreData ) ||
	 ( BytesRead > BufLen ) ||
	 ( BytesRead > MAXPASSWDLEN -1 ) )
    {
	syslog( LOG_NOTICE, "%s: Base64 encoded password sent from client on sd %d is too large.", fn, Client->conn->sd );
	return( -1 );
    }
    
    memcpy( (void *)EncodedPassword, (const void *)Client->ReadBuf, 
	    BytesRead - 2 );

    rc = EVP_DecodeBlock( Password, EncodedPassword, BytesRead - 2 );
    Password[rc] = '\0';
    
    if ( getpeername( Client->conn->sd, (struct sockaddr *)&cli_addr, 
		      &sockaddrlen ) < 0 )
    {
	syslog( LOG_WARNING, "AUTH_LOGIN: user '%s' failed: getpeername() failed for client sd: %s", Username, strerror( errno ) );
	return( -1 );
    }
    
    if ( getnameinfo( (struct sockaddr *) &cli_addr, sockaddrlen,
		      hostaddr, sizeof hostaddr, portstr, sizeof portstr,
		      NI_NUMERICHOST | NI_NUMERICSERV ) )
    {
        syslog( LOG_WARNING,
		"AUTH_LOGIN: '%s' failed: getnameinfo() failed for client sd: %s",
		Username, strerror( errno ) );
        return( -1 );
    }
    

    /*
     * Tell Get_Server_conn() to send the password as a string literal if
     * he needs to login.  This is just in case there are any special
     * characters in the password that we decoded.
     */
    conn = Get_Server_conn( Username, Password, hostaddr, portstr, LITERAL_PASSWORD, fullServerResponse );
    
    /*
     * all the code from here to the end is basically identical to that
     * in cmd_login().
     */
    
    memset( Password, 0, MAXPASSWDLEN );
    
    if ( conn == NULL )
    {
	// When we get a NO or BAD, we'll relay the original/full
	// server response to the client in case it contains anything
	// useful (such as RFC 5530 response codes).  We'll use our
	// own generic NO response otherwise (RFC 3501 doesn't allow
	// other responses)
	//
	if ( !memcmp( (const void *)fullServerResponse, "NO", 2 )
	  || !memcmp( (const void *)fullServerResponse, "BAD", 3 ) )
	{
	    snprintf( SendBuf, BufLen, "%s %s\r\n", Tag, fullServerResponse );
	}
	else
	    snprintf( SendBuf, BufLen, "%s NO AUTHENTICATE failed\r\n", Tag );
	
	if ( IMAP_Write( Client->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog( LOG_ERR, "%s: Unable to send failure message back to client: %s", fn, strerror( errno ) );
	    return( -1 );
	}
	return( 0 );
    }
    
    Server.conn = conn;

    /*
     * If the connection has been reused, send a status response indicating
     * this.
     */
    if (Server.conn->reused == 1)
    {
	sprintf( SendBuf, "* OK [XPROXYREUSE] IMAP connection reused by squirrelmail-imap_proxy\r\n" );
	if ( IMAP_Write( Client->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog(LOG_ERR, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	    return( -1 );
	}
    }
    
// TODO: under what circumstances do we want to pass through the server's full OK response? (usually a CAPABILITY string)
    //if ( !memcmp( (const void *)fullServerResponse, "OK", 2 ) )
    if (0)
	snprintf( SendBuf, BufLen, "%s %s\r\n", Tag, fullServerResponse );
    else
	snprintf( SendBuf, BufLen, "%s OK User authenticated\r\n", Tag );

    if ( IMAP_Write( Client->conn, SendBuf, strlen( SendBuf ) ) == -1 )
    {
	IMAPCount->InUseServerConnections--;
    ICC_Invalidate(Server.conn->ICC);
	syslog( LOG_ERR, "%s: Unable to send successful authentication message back to client: %s -- closing connection.", fn, strerror( errno ) );
	return( -1 );
    }
    
    IMAPCount->TotalClientLogins++;
    
    LockMutex ( &trace );
    if ( ! strcmp( Username, TraceUser ) )
    {
	Client->TraceOn = 1;
	Server.TraceOn = 1;
    }
    else
    {
	Client->TraceOn = 0;
	Server.TraceOn = 0;
    }
    UnLockMutex( &trace );

    rc = Raw_Proxy( Client, &Server, &Server.conn->ISC );
    
    if (rc == -2) {
        ICC_Invalidate( Server.conn->ICC );
        return ( -1 );
    }

    Client->TraceOn = 0;
    Server.TraceOn = 0;
    
    ICC_Logout( Server.conn->ICC );
    
    return( rc );
}




/*++
 * Function:	cmd_login
 *
 * Purpose:	implement the LOGIN IMAP command.
 *
 * Parameters:	ptr to ITD_Struct for client connection.
 *              ptr to username
 *              ptr to password
 *              int length of password buffer
 *              ptr to client tag
 *              unsigned char - flag to indicate literal password in login
 *                              command.
 *
 * Returns:	0 on success prior to authentication
 *              1 on success after authentication (we caught a logout)
 *		-1 on failure
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Note:        Not too many things are really considered "failure" in the
 *              context of this routine, because returning failure would
 *              result in the client connection being closed.  When most
 *              things fail, we'll send a failure response to the client,
 *              but return success to the caller.  That will allow the
 *              client to know that something broke and try again if it
 *              wants to.
 *
 *--
 */
static int cmd_login( ITD_Struct *Client, 
		      char *Username, 
		      char *Password,
		      int passlen,
		      char *Tag,
		      unsigned char LiteralLogin )
{
    char *fn = "cmd_login()";
    char SendBuf[BUFSIZE];
    unsigned int BufLen = BUFSIZE - 1;
    ITD_Struct Server;
    int rc;
    ICD_Struct *conn;
    char fullServerResponse[BUFSIZE] = "\0\0\0";
    struct sockaddr_storage cli_addr;
    int sockaddrlen;
    char hostaddr[INET6_ADDRSTRLEN], portstr[NI_MAXSERV];

    memset( &Server, 0, sizeof Server );

    sockaddrlen = sizeof( struct sockaddr_storage );

    if ( getpeername( Client->conn->sd, (struct sockaddr *)&cli_addr, 
		      &sockaddrlen ) < 0 )
    {
	syslog(LOG_INFO, "LOGIN: '%s' failed: getpeername() failed for client sd: %s", Username, strerror( errno ) );
	return( -1 );
    }
    
    if ( getnameinfo( (struct sockaddr *) &cli_addr, sockaddrlen,
		      hostaddr, sizeof hostaddr, portstr, sizeof portstr,
		      NI_NUMERICHOST | NI_NUMERICSERV ) )
    {
        syslog( LOG_INFO,
		"LOGIN: '%s' failed: getnameinfo() failed for client sd: %s",
		Username, strerror( errno ) );
	return( -1 );
    }
    
    conn = Get_Server_conn( Username, Password, hostaddr, portstr, LiteralLogin, fullServerResponse );

    /*
     * wipe out the passwd so we don't have it sitting in memory somewhere.
     */
    memset( Password, 0, passlen );
    
        
    if ( conn == NULL )
    {
	/*
	 * All logging is done in Get_Server_conn, so don't bother to
	 * log anything here.
	 *
	 * When we get a NO or BAD, we'll relay the original/full
	 * server response to the client in case it contains anything
	 * useful (such as RFC 5530 response codes).  We'll use our
	 * own generic NO response otherwise (RFC 3501 doesn't allow
	 * other responses)
	 */
	if ( !memcmp( (const void *)fullServerResponse, "NO", 2 )
	  || !memcmp( (const void *)fullServerResponse, "BAD", 3 ) )
	{
	    snprintf( SendBuf, BufLen, "%s %s\r\n", Tag, fullServerResponse );
	}
	else
	    snprintf( SendBuf, BufLen, "%s NO LOGIN failed\r\n", Tag );
	
	if ( IMAP_Write( Client->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog(LOG_ERR, "%s: Unable to send failure message back to client: %s", fn, strerror(errno) );
	    return( -1 );
	}
	return( 0 );
    }
    
    Server.conn = conn;

    /*
     * If the connection has been reused, send a status response indicating
     * this.
     */
    if (Server.conn->reused == 1)
    {
	sprintf( SendBuf, "* OK [XPROXYREUSE] IMAP connection reused by squirrelmail-imap_proxy\r\n" );
	if ( IMAP_Write( Client->conn, SendBuf, strlen(SendBuf) ) == -1 )
	{
	    syslog(LOG_ERR, "%s: IMAP_Write() failed: %s", fn, strerror(errno) );
	    return( -1 );
	}
    }

    /*
     * Send a success message back to the client
     * and go into raw proxy mode.
     */
// TODO: under what circumstances do we want to pass through the server's full OK response? (usually a CAPABILITY string)
    //if ( !memcmp( (const void *)fullServerResponse, "OK", 2 ) )
    if (0)
	snprintf( SendBuf, BufLen, "%s %s\r\n", Tag, fullServerResponse );
    else
	snprintf( SendBuf, BufLen, "%s OK User logged in\r\n", Tag );
    if ( IMAP_Write( Client->conn, SendBuf, strlen(SendBuf) ) == -1 )
    {
	/*
	 * This really sux.  We successfully logged the user in, but now
	 * we can't communicate with the client...
	 */
	IMAPCount->InUseServerConnections--;
    ICC_Invalidate(Server.conn->ICC);
	syslog(LOG_ERR, "%s: Unable to send successful login message back to client: %s -- closing connection.", fn, strerror(errno) );
	return( -1 );
    }

    IMAPCount->TotalClientLogins++;
    
    /* turn on tracing for this session if necessary */
    LockMutex( &trace );
    if ( ! strcmp( Username, TraceUser ) )
    {
	Client->TraceOn = 1;
	Server.TraceOn = 1;
    }
    else
    {
	Client->TraceOn = 0;
	Server.TraceOn = 0;
    }
    UnLockMutex( &trace );

    rc = Raw_Proxy( Client, &Server, &Server.conn->ISC );

    if (rc == -2) {
        ICC_Invalidate( Server.conn->ICC );
        return ( -1 );
    }

    /*
     * It's not necessary to take out the trace mutex here.  The reason
     * we take it out when we check above is because the trace username
     * could change at any time.  When we disable tracing here, we're
     * doing it regardless of what the trace username is, so we don't 
     * take out the mutex.
     */
    Client->TraceOn = 0;
    Server.TraceOn = 0;
    
    /* update the logout time for this cached connection */
    ICC_Logout( Server.conn->ICC );
    
    return( rc );
}




/*++
 * Function:	Raw_Proxy
 *
 * Purpose:	Start a raw proxy session to the IMAP server, catching only
 *		LOGOUT commands from the client.
 *
 * Parameters:	ptr to client ITD_Struct
 *		ptr to server ITD_Struct
 *
 * Returns:	1 if we caught a logout
 *		-1 on failure on client
 *		-2 on failure on server or fatal
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *--
 */
static int Raw_Proxy( ITD_Struct *Client, ITD_Struct *Server,
		      ISC_Struct *ISC )
{
    char *fn = "Raw_Proxy()";
    struct pollfd fds[2];
    nfds_t nfds;
    int status, pending;
    unsigned int FailCount;
    int BytesSent;
    char *CP;
    char TraceBuf[ BUFSIZE ];
    char SendBuf[ BUFSIZE ];
    int rc;
    
#define SERVER 0
#define CLIENT 1
    
    FailCount = 0;
    nfds = 2;
    
    /*
     * Set up our fds structs.
     */
    fds[ SERVER ].fd = Server->conn->sd;
    fds[ CLIENT ].fd = Client->conn->sd;
    
    fds[ SERVER ].events = POLLIN;
    fds[ CLIENT ].events = POLLIN;

    /*
     * POLL loop
     */
    for ( ; ; )
    {
	pending = 0;
	fds[ SERVER ].revents = 0;
	fds[ CLIENT ].revents = 0;
	
#if HAVE_LIBSSL
	if ( Server->conn->tls )
	{
	    /* See is we have any buffered input */
	    pending = SSL_pending( Server->conn->tls );
	}
#endif

	status = ( pending ? 1 : poll( fds, nfds, POLL_TIMEOUT ) );
	
	/*
	 * poll returns a non-negative value on success.
	 * it returns 0 if it times out before any revents are modified.
	 * -1 is returned on failure.
	 */
	if ( !status )
	{
	    /*
	     * We timed out.  End result is that we want the server and
	     * client sides of this connection to close.  The nicest way
	     * to have this happen will be to simply return failure to
	     * cmd_login().
	     * We were called by HandleRequest() & then cmd_login().  When
	     * we return -1 to cmd_login(), he'll call ICC_Logout() to
	     * update the logout time for this user on this server sd.
	     * Eventually, the ICC_Recycle thread will wake up and reap the
	     * server-side of the connection.
	     * cmd_login() will return our -1 to Handle_Request
	     * and HandleRequest will close the client-side socket.
	     */
	    syslog( LOG_WARNING, "%s: poll() timed out. server sd [%d]. client sd [%d].", fn, Server->conn->sd, Client->conn->sd );
	    /*
	     * Update - thanks to Jose Celestino's patch, we have a way to
	     * immediately ensure the server connection is shut down and
	     * not reused - for situations where we get server or other
	     * anomalous errors.  So we'll return -2 here instead, which
	     * will trigger cmd_login() or cmd_authenticate_login() (the
	     * only two callers of this function) to take care of the
	     * server connection right away and return -1 to HandleRequest()
	     * which then just closes the client connection as usual.
	     */
	    return( -2 );
	}
	
	if ( status < 0 )
	{
	    /* If we were interrupted by a signal, just continue the loop. */
	    if ( errno == EINTR )
	    {
		syslog(LOG_INFO, "%s: poll() was interrupted by a signal -- continuing.", fn);
		continue;
	    }
	    
	    
	    /* resource issue -- try again. */
	    if ( errno == EAGAIN )
	    {
		FailCount++;
		if ( FailCount == 5 )
		{
		    syslog(LOG_ERR, "%s: poll() returned EAGAIN.  Exceeded retry limit.  Returning failure.", fn );
		    return( -1 );
		}
		
		syslog(LOG_WARNING,"%s: poll() returned EAGAIN.  Retrying.", fn );
		sleep(5);
		continue;
	    }

	    /* anything else, we're really jacked about it. */
	    syslog(LOG_ERR, "%s: poll() failed: %s -- Returning failure.", fn, strerror( errno ) );
	    return( -2 );
	}
	
	FailCount = 0;
	

	/*
	 * PROXY LOOPS
	 */

	/*
	 * Check the server first to see if he has any data to send.  I don't
	 * know if the order (client or server) matters, but my logic is that
	 * the client should always be ready to hear from the server since the
	 * server is allowed to send unsolicited data and the client has to
	 * be able to deal with it.
	 */
	if ( pending || fds[ SERVER ].revents )
	{
	    for ( ; ; )
	    {
		status = IMAP_Read( Server->conn, Server->ReadBuf, 
			       sizeof Server->ReadBuf );
		
		if ( status == -1 )
		{
		    if ( errno == EINTR )
			continue;
		    
		    syslog(LOG_WARNING, "%s: IMAP_Read() failed reading from IMAP server on sd [%d]: %s", fn, Server->conn->sd, strerror( errno ) );
		    return( -2 );
		}
		break;
	    }
	    
	    if ( status == 0 )
	    {
		/* the server closed the connection, dammit */
		syslog(LOG_ERR, "%s: IMAP server unexpectedly closed the connection on sd %d", fn, Server->conn->sd );
		return( -2 );
	    }
	    
	    if ( Server->TraceOn )
	    {
		snprintf( TraceBuf, sizeof TraceBuf - 1, "\n\n-----> C= %d %s SERVER: sd [%d]\n",
		    (int)time(0), ( (*TraceUser) ? TraceUser : "Null username" ), Server->conn->sd );
		write( Tracefd, TraceBuf, strlen( TraceBuf ) );
		write( Tracefd, Server->ReadBuf, status );
	    }
	    
	    /* whatever we read from the server, ship off to the client */
	    for ( ; ; )
	    {
		BytesSent = IMAP_Write( Client->conn, Server->ReadBuf, status );
		
		if ( BytesSent == -1 )
		{
		    if ( errno == EINTR )
			continue;
		    
		    syslog(LOG_ERR, "%s: IMAP_Write() failed sending data to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
		    return( -1 );
		}
		break;
	    }  /* end of infinite for loop for IMAP_Write() to client */
	}          /* end of if conditional -- were there server sd events? */
	
	
	/*
	 * Now we proxy from the client to the server.  We have to watch
	 * this side a little bit closer...
	 */
	if ( ! fds[ CLIENT ].revents )
	{
	    continue;
	}

	do
	{
	    do 
	    {
		status = IMAP_Line_Read( Client );
		
		if ( status == -1 )
		{
		    syslog(LOG_NOTICE, "%s: Failed to read line from client on socket %d", fn, Client->conn->sd );
		    return( -1 );
		}
	    
		if ( Client->TraceOn )
		{
		    snprintf( TraceBuf, sizeof TraceBuf - 1, "\n\n-----> C= %d %s CLIENT: sd [%d]\n", (int)time(0), ( (*TraceUser) ? TraceUser : "Null username" ), Client->conn->sd );
		    write( Tracefd, TraceBuf, strlen( TraceBuf ) );
		    write( Tracefd, Client->ReadBuf, status );
		}
		
	    
		/* 
		 * This is a command.  What command is it?
		 */
		CP = memchr( Client->ReadBuf, ' ',
			     Client->ReadBytesProcessed );
	    
		if ( CP )
		{
		    CP++;
		    
		    if ( !strncasecmp( CP, "LOGOUT", 6 ) )
		    {
			/*
			 * Since we want to potentially reuse this server
			 * connection, we want to return it to an unselected 
			 * state.  Use UNSELECT if the server supports it.
			 * Otherwise, EXAMINE a null mailbox.  If SELECT
			 * caching is enabled, don't do this.
			 */
			if ( ! PC_Struct.enable_select_cache )
			{
			    snprintf( SendBuf, sizeof SendBuf - 1,
				      "C64 %s\r\n", ( (PC_Struct.support_unselect) ? "UNSELECT" : "EXAMINE \"\"" ) );
			    
			    IMAP_Write( Server->conn, SendBuf,
					strlen(SendBuf) );
			    /*
			     * To be more correct, we should send any untagged
			     * data back to the client before we're done.
			     */
			    for( ;; )
			    {
				/*
				 * If the server wants to send a literal for
				 * some reason, bag it...
				 */
				if ( Server->LiteralBytesRemaining )
				    break;
				
				status = IMAP_Line_Read( Server );
				
				/*
				 * If there's an error reading from the server,
				 * we'll catch it when (if) we try to reuse this
				 * connection.
				 */
				if ( ( status == -1 ) || ( status == 0 ) )
				    break;
			    
				/*
				 * If it's not untagged data, we're done.
				 */
				if ( Server->ReadBuf[0] != '*' )
				    break;
				
				BytesSent = IMAP_Write( Client->conn, 
							Server->ReadBuf, status );
				if ( BytesSent == -1 )
				{
				    syslog( LOG_ERR, "%s: IMAP_Write() failed sending data to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
				}
			    }
			} /* if ( ! PC_Struct.enable_select_cache ) */

			memset( Server->ReadBuf, 0, sizeof Server->ReadBuf );
			
			return( 1 );
		    }
		
		    /*
		     * it's some command other than a LOGOUT...
		     * If we care about SELECT caching, do that now.
		     */
		    if ( PC_Struct.enable_select_cache )
		    {
			if ( !strncasecmp( CP, "SELECT ", 7 ) )
			{
			    rc = Handle_Select_Command( Client, Server,
							ISC, Client->ReadBuf,
							status );
			    
			    if ( rc == 0 )
				continue;

			    if ( rc < 0 ) // -1 or -2
				return( rc );

			    /* 
			     * if Handle_Select_Command() returned 1,
			     * fall through the rest of the logic and the
			     * SELECT command should be proxied without
			     * looking at the cache.
			     */
			    
			} /* if the command is SELECT */

			/*
			 * SELECT caching is enabled and we've encountered
			 * a command other than SELECT.  See if we should
			 * invalidate the SELECT cache or not.
			 */
			if ( ! Is_Safe_Command( CP ) )
			{
			    Invalidate_Cache_Entry( ISC );
			}
			
		    } /* if ( PC_Struct.enable_select_cache ) */
		    
		} /* if ( CP ) */
		

		for ( ; ; )
		{
		    BytesSent = IMAP_Write( Server->conn, Client->ReadBuf, status );
		    if ( BytesSent == -1 )
		    {
			if ( errno == EINTR )
			    continue;
			
			syslog(LOG_ERR, "%s: IMAP_Write() failed sending data to server on sd [%d]: %s", fn, Server->conn->sd, strerror( errno ) );
			return( -2 );
		    }
		    break;
		}
		
		/*
		 * Don't just rely on our do/while condition.  There
		 * may still be stuff in our buffer, but it could be
		 * literal data.  Check and break out of the loop if that's
		 * the case.
		 */
		if ( Client->LiteralBytesRemaining )
		    break;
		
	    } while ( Client->BytesInReadBuffer > Client->ReadBytesProcessed );
	    
	    
	    /* 
	     * If there are literal bytes to read, get them and blast them
	     * off to the server.  Only do this, however, if it's a non
	     * synchronous literal since the server has to send a "go ahead"
	     * otherwise.
	     */
	    if ( ! Client->LiteralBytesRemaining )
		continue;
	    
	    
	    /*
	     * Do we have to wait for a "go-ahead" from the server?
	     */
	    if ( ! Client->NonSyncLiteral )
	    {
		/* we have to wait for a go-ahead */
		status = IMAP_Line_Read( Server );
		if ( Server->TraceOn )
		{
		    snprintf( TraceBuf, sizeof TraceBuf - 1, "\n\n-----> C= %d %s SERVER: sd [%d]\n", (int)time(0), ( (*TraceUser) ? TraceUser : "Null username" ), Server->conn->sd );
		    write( Tracefd, TraceBuf, strlen( TraceBuf ) );
		    write( Tracefd, Server->ReadBuf, status );
		}

		if ( Server->ReadBuf[0] != '+' )
		    Client->LiteralBytesRemaining = 0;

		for ( ; ; )
		{
		    BytesSent = IMAP_Write( Client->conn, Server->ReadBuf, status );
		    if ( BytesSent == -1 )
		    {
			if ( errno == EINTR )
			    continue;
			
			syslog(LOG_ERR, "%s: IMAP_Write() failed sending data to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
			return( -1 );
		    } 
		    break;
		}
	    }

	    while ( Client->LiteralBytesRemaining )
	    {
		status = IMAP_Literal_Read( Client );
		
		if ( status == -1 )
		{
		    syslog(LOG_NOTICE, "%s: Failed to read string literal from client on socket %d", fn, Client->conn->sd );
		    return( -1 );
		}

		if ( Client->TraceOn )
		{
		    snprintf( TraceBuf, sizeof TraceBuf - 1, "\n\n-----> C= %d %s CLIENT: sd [%d]\n", (int)time(0), ( (*TraceUser) ? TraceUser : "Null username" ), Client->conn->sd );
		    write( Tracefd, TraceBuf, strlen( TraceBuf ) );
		    write( Tracefd, Client->ReadBuf, status );
		}
		
		/* send any literal data back to the server */
		for ( ; ; )
		{
		    BytesSent = IMAP_Write( Server->conn, Client->ReadBuf, status );
		    if ( BytesSent == -1 )
		    {
			if ( errno == EINTR )
			    continue;
			
			syslog(LOG_ERR, "%s: IMAP_Write() failed sending data to server on sd [%d]: %s", fn, Server->conn->sd, strerror( errno ) );
			return( -2 );
		    }
		    break;
		}
		
	    }
	    
	} while ( Client->BytesInReadBuffer > Client->ReadBytesProcessed );
	
    }
    
}



    




/*++
 * Function:	HandleRequest
 *
 * Purpose:	Handle incoming IMAP requests (as a thread)
 *
 * Parameters:	int, client socket descriptor
 *
 * Returns:	nada
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:	This function actually only handles unauthenticated
 *		traffic from an IMAP client.  As such it can only make sense
 *		of the following IMAP commands (rfc 2060):  NOOP, CAPABILITY,
 *		AUTHENTICATE, LOGIN, and LOGOUT.  Also, it handles the
 *              commands that are internal to the proxy server such as
 *              XPROXY_TRACE, XPROXY_NEWLOG, XPROXY_DUMPICC,
 *              XPROXY_RESETCOUNTERS and XPROXY_VERSION.
 *
 *              None of these commands should ever have the need to send
 *              a boatload of data, so we avoid some error checking and
 *              undue complexity in this routine by just making sure that
 *              any given read from the client doesn't fill our read
 *              buffer.  If it does, we just drop the connection.
 *--
 */
extern void HandleRequest( int clientsd )
{
    char *fn = "HandleRequest";
    ITD_Struct Client;
    ICD_Struct conn;
    char *Tag;
    char *Command;
    char *Username;
    char *AuthMech;
    char *Lasts;
    char *EndOfLine;
    char *CP;
    char SendBuf[BUFSIZE];
    int BytesRead;
    int rc;
    unsigned int BufLen = BUFSIZE - 1;
    char S_UserName[MAXUSERNAMELEN];
    char S_Tag[MAXTAGLEN];
    char S_Password[MAXPASSWDLEN];
    unsigned char LiteralFlag;          /* flag to deal with passwords sent */
					/* as string literals */
    
    
    struct pollfd fds[1];
    nfds_t nfds;
    int PollFailCount;
    
    PollFailCount = 0;
    
    /* initialize the client ITD */
    memset( &Client, 0, sizeof( ITD_Struct ) );
    memset( &conn, 0, sizeof( ICD_Struct ) );
    Client.conn = &conn;
    Client.conn->sd = clientsd;


    /* send the banner to the client */
    if ( IMAP_Write( Client.conn, Banner, BannerLen ) == -1 )
    {
	syslog(LOG_ERR, "%s: IMAP_Write() failed: %s.  Closing client connection.", fn, strerror( errno ) );
	IMAPCount->CurrentClientConnections--;
	close( Client.conn->sd );
	return;
    }
    

    /* set up our poll fd structs */
    nfds = 1;
    
    fds[ 0 ].fd = Client.conn->sd;
    fds[ 0 ].events = POLLIN;
    
    /* start a command loop */
    for ( ; ; )
    {
	LiteralFlag = NON_LITERAL_PASSWORD;

	fds[ 0 ].revents = 0;
	
	rc = poll( fds, nfds, POLL_TIMEOUT );
	
	if ( !rc )
	{
	    /*
	     * our client timeout was exceeded.  Drop this connection.
	     */
	    syslog(LOG_ERR, "%s: no data received from client for %d minutes.  Closing client connection.", fn, POLL_TIMEOUT_MINUTES );
	    IMAPCount->CurrentClientConnections--;
	    close( Client.conn->sd );
	    return;
	}
	
	if ( rc < 0 )
	{
	    /* If we were interrupted by a signal, just continue the loop. */
	    if ( errno == EINTR )
	    {
		syslog(LOG_INFO, "%s: poll() was interrupted by a signal -- continuing.", fn);
		continue;
	    }
	    
	    
	    /* resource issue -- try again. */
	    if ( errno == EAGAIN )
	    {
		PollFailCount++;
		if ( PollFailCount == 5 )
		{
		    syslog(LOG_ERR, "%s: poll() returned EAGAIN.  Exceeded retry limit.  Closing client connection.", fn );
		    IMAPCount->CurrentClientConnections--;
		    close( Client.conn->sd );
		    return;
		}
		
		syslog(LOG_WARNING, "%s: poll() returned EAGAIN.  Retrying.", fn );
		sleep(5);
		continue;
	    }
	    
	    /* anything else, we're really jacked about it. */
	    syslog(LOG_ERR, "%s: poll() failed: %s -- Closing connection.", fn, strerror( errno ) );
	    IMAPCount->CurrentClientConnections--;
	    close( Client.conn->sd );
	    return;
	}
	
	PollFailCount = 0;

	BytesRead = IMAP_Line_Read( &Client );

	if ( BytesRead == -1 )
	{
	    IMAPCount->CurrentClientConnections--;
	    close( Client.conn->sd );
	    return;
	}
	
	if ( Client.MoreData )
	{
	    syslog( LOG_WARNING, "%s: Too much data read from unauthenticated client.  Dropping the connection.", fn );
	    IMAPCount->CurrentClientConnections--;
	    close( Client.conn->sd );
	    return;
	}
	
	
    	/* First grab the tag */
	
	EndOfLine = Client.ReadBuf + BytesRead;

	Tag = memtok( Client.ReadBuf, EndOfLine, &Lasts );
	if ( ( !Tag ) ||
	     ( !imparse_isatom( Tag ) ) ||
	     ( Tag[0] == '*' && !Tag[1] ) )
	{
	    snprintf( SendBuf, BufLen, "* BAD Invalid tag\r\n" );
	    if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
	    {
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    continue;
	}
	

	Command = memtok( NULL, EndOfLine, &Lasts );
	if ( !Command )
	{
	    /* Tag with no command */
	    snprintf( SendBuf, BufLen, "%s BAD Null command\r\n", Tag );
	    if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
	    {
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    continue;
	}
	
	/*
	 * We should have a valid tag and command now.  React as
	 * appropriate...
	 */
	strncpy( S_Tag, Tag, MAXTAGLEN - 1 );
	S_Tag[ MAXTAGLEN - 1 ] = '\0';
	
	if ( ! strcasecmp( (const char *)Command, "NOOP" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of NOOP command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    
	    cmd_noop( &Client, S_Tag );
	    continue;
	}
	else if ( ! strcasecmp( (const char *)Command, "CAPABILITY" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of CAPABILITY command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    cmd_capability( &Client, S_Tag );
	    continue;
	}
	else if ( ! strcasecmp( (const char *)Command, "AUTHENTICATE" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of AUTHENTICATE command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    AuthMech = memtok( NULL, EndOfLine, &Lasts );
	    if ( !AuthMech )
	    {
		snprintf( SendBuf, BufLen, "%s BAD Missing required argument to Authenticate\r\n", Tag );
		if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		{
		    IMAPCount->CurrentClientConnections--;
		    close( Client.conn->sd );
		    return;
		}
		continue;
	    }
	    
	    if ( !strcasecmp( (const char *)AuthMech, "LOGIN" ) )
	    {
		rc = cmd_authenticate_login( &Client, S_Tag );

		if ( rc == 0 )
		    continue;
		
		if ( rc == 1 )
		{
		    /* caught a logout */
		    Tag = memtok( Client.ReadBuf, EndOfLine, &Lasts );
		    if ( Tag )
		    {
			strncpy( S_Tag, Tag, MAXTAGLEN - 1 );
			S_Tag[ MAXTAGLEN - 1 ] = '\0';
			cmd_logout( &Client, S_Tag );
		    }
		}
		
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    else if ( !strcasecmp( (const char *)AuthMech, "PLAIN" ) )
	    {
		/*
		 * we handle this mechanism, but internally; not as
		 * requested by a client
		 */
		snprintf( SendBuf, BufLen, "%s NO no mechanism available, we do something different!\r\n", Tag );
		if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		{
		    IMAPCount->CurrentClientConnections--;
		    close( Client.conn->sd );
		    return;
		}
		continue;
	    }
	    else
	    {
		/*
		 * an auth mechanism we can't handle.
		 */
		snprintf( SendBuf, BufLen, "%s NO no mechanism available\r\n", Tag );
		if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		{
		    IMAPCount->CurrentClientConnections--;
		    close( Client.conn->sd );
		    return;
		}
		continue;
	    }
	    
	}
	else if ( ! strcasecmp( (const char *)Command, "LOGOUT" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of LOGOUT command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    cmd_logout( &Client, S_Tag );
	    IMAPCount->CurrentClientConnections--;
	    close( Client.conn->sd );
	    return;
	}
	else if ( ! strcasecmp( (const char *)Command, "XPROXY_TRACE" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of P_TRACE command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    Username = memtok( NULL, EndOfLine, &Lasts );
	    cmd_trace( &Client, S_Tag, Username );
	    continue;
	}
	else if ( ! strcasecmp( (const char *)Command, "XPROXY_DUMPICC" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of P_DUMPICC command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    cmd_dumpicc( &Client, S_Tag );
	    continue;
	}
	else if ( ! strcasecmp( (const char *)Command, "XPROXY_RESETCOUNTERS" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of P_RESETCOUNTERS command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    cmd_resetcounters( &Client, S_Tag );
	    continue;
	}
	else if ( ! strcasecmp( (const char *)Command, "XPROXY_NEWLOG" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of P_NEWLOG command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    cmd_newlog( &Client, S_Tag );
	    continue;
	}
	else if ( ! strcasecmp( (const char *)Command, "XPROXY_VERSION" ) )
	{
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of P_VERSION command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    cmd_version( &Client, S_Tag );
	    continue;
	}
	else if ( ! strcasecmp( (const char *)Command, "LOGIN" ) )
	{
	    /*
	     * Got a LOGIN command.  validate that we got all four required
	     * tokens (Tag, Command, Username, Password) before we waste
	     * a connection to the IMAP server.
	     */
	    Username = memtok( NULL, EndOfLine, &Lasts );
	    if ( !Username )
	    {
		/* no username -- complain back to the client */
		snprintf( SendBuf, BufLen, "%s BAD Missing required argument to Login\r\n", Tag );
		if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		{
		    IMAPCount->CurrentClientConnections--;
		    close( Client.conn->sd );
		    return;
		}
		continue;
	    }
	    strncpy( S_UserName, Username, sizeof S_UserName - 1 );
	    S_UserName[ sizeof S_UserName - 1 ] = '\0';
	    
	    /*
	     * Clients can send the username as a literal bytestream.  Check
	     * for that here (the username we grabbed above will actually
	     * be the literal token itself (the ONLY token on the line)
	     * instead of the real username).
	     */
	    if ( Client.LiteralBytesRemaining
	     && memtok( NULL, EndOfLine, &Lasts ) == NULL
	     && S_UserName[ 0 ] == '{' && S_UserName[ strlen( S_UserName ) - 1 ] == '}' )
	    {

		if ( ( sizeof S_UserName - 1 ) < Client.LiteralBytesRemaining )
		{
		    syslog( LOG_ERR, "%s: username length would cause buffer overflow.", fn );
		    /*
		     * we have to at least eat the literal bytestream because
		     * of the way our I/O routines work.
		     */
		    memset( &Client.ReadBuf, 0, sizeof Client.ReadBuf );
		    Client.BytesInReadBuffer = 0;
		    Client.ReadBytesProcessed = 0;
		    Client.LiteralBytesRemaining = 0;
		    Client.NonSyncLiteral = 0;
		    Client.MoreData = 0;
		    
		    snprintf( SendBuf, BufLen, "%s NO LOGIN failed\r\n", S_Tag );
		    if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		    {
			IMAPCount->CurrentClientConnections--;
			close( Client.conn->sd );
			return;
		    }
		    continue;
		}

		CP = S_UserName;

		if ( ! Client.NonSyncLiteral )
		{
		    sprintf( SendBuf, "+ go ahead\r\n" );
		    if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		    {
			IMAPCount->CurrentClientConnections--;
			close( Client.conn->sd );
			return;
		    }
		}

		while ( Client.LiteralBytesRemaining )
		{
		    BytesRead = IMAP_Literal_Read( &Client );
		    
		    if ( BytesRead == -1 )
		    {
			syslog( LOG_NOTICE, "%s: Failed to read string literal from client on login.", fn );
			snprintf( SendBuf, BufLen, "%s NO LOGIN failed\r\n", S_Tag );
			if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
			{
			    IMAPCount->CurrentClientConnections--;
			    close( Client.conn->sd );
			    return;
			}
			continue;
		    }
		    
		    memcpy ( (void *)CP, (const void *)Client.ReadBuf, BytesRead );
		    CP += BytesRead;
		}
		*CP = '\0';

		/*
		 * Thankfully, IMAP_Literal_Read() leaves the rest of
		 * the line in buffer, so we can read the rest now and
		 * let the code below grab the password as usual, being
		 * careful to reset our read/token pointers
		 */
		BytesRead = IMAP_Line_Read( &Client );
		EndOfLine = Client.ReadBuf + BytesRead;
		Lasts = Client.ReadBuf;

	    }

	    /*
	     * Clients can send the password as a literal bytestream.  Check
	     * for that here.
	     */
	    if ( Client.LiteralBytesRemaining )
	    {
		if ( ( sizeof S_Password - 1 ) < Client.LiteralBytesRemaining )
		{
		    syslog( LOG_ERR, "%s: password length would cause buffer overflow.", fn );
		    /*
		     * we have to at least eat the literal bytestream because
		     * of the way our I/O routines work.
		     */
		    memset( &Client.ReadBuf, 0, sizeof Client.ReadBuf );
		    Client.BytesInReadBuffer = 0;
		    Client.ReadBytesProcessed = 0;
		    Client.LiteralBytesRemaining = 0;
		    Client.NonSyncLiteral = 0;
		    Client.MoreData = 0;

		    snprintf( SendBuf, BufLen, "%s NO LOGIN failed\r\n", S_Tag );
		    if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		    {
			IMAPCount->CurrentClientConnections--;
			close( Client.conn->sd );
			return;
		    }
		    continue;
		}
	
		LiteralFlag = LITERAL_PASSWORD;
		
		CP = S_Password;

		if ( ! Client.NonSyncLiteral )
		{
		    sprintf( SendBuf, "+ go ahead\r\n" );
		    if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		    {
			IMAPCount->CurrentClientConnections--;
			close( Client.conn->sd );
			return;
		    }
		}

		while ( Client.LiteralBytesRemaining )
		{
		    BytesRead = IMAP_Literal_Read( &Client );
		    
		    if ( BytesRead == -1 )
		    {
			syslog( LOG_NOTICE, "%s: Failed to read string literal from client on login.", fn );
			snprintf( SendBuf, BufLen, "%s NO LOGIN failed\r\n", S_Tag );
			if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
			{
			    IMAPCount->CurrentClientConnections--;
			    close( Client.conn->sd );
			    return;
			}
			continue;
		    }
		    
		    memcpy ( (void *)CP, (const void *)Client.ReadBuf, BytesRead );
		    CP += BytesRead;
		}
		*CP = '\0';

		/*
		 * I'm not sure if IMAP_Literal_Read() is written entirely
		 * in a correct fashion.  There will be a CRLF at the end
		 * of the literal bytestream that it doesn't deal with.
		 * If we don't eat that here, it will be read as a separate
		 * (Null) command...  Reading it here is more of a hack than
		 * a real solution, but I hesitate to fiddle with 
		 * IMAP_Literal_Read() right now since it works properly
		 * otherwise.
		 * Note: from the perspective of a naive user of this function
		 * (elsewhere), the fact that it leaves the rest of the line
		 * in the buffer is very helpful, so I'd say don't change that
		 * behavior!
		 */
		rc = IMAP_Line_Read( &Client );
	    }
	    else
	    {
		/*
		 * The password is just being sent as a plain old string.
		 * Can't use memtok() because it uses a single space as the
		 * token delimeter and any password with a space in it would
		 * break.
		 */
		CP = EndOfLine - 2;
		Lasts++;
		
		if ( Lasts >= CP )
		{
		    /* no password -- complain back to the client */
		    snprintf( SendBuf, BufLen, "%s BAD Missing required argument to Login\r\n", S_Tag );
		    if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
		    {
			IMAPCount->CurrentClientConnections--;
			close( Client.conn->sd );
			return;
		    }
		    continue;
		}
		
		*CP = '\0';
		strncpy( S_Password, Lasts, sizeof S_Password - 1 );
		S_Password[ sizeof S_Password - 1 ] = '\0';
	    }
	    

	    
	    /*
	     * wipe out the the client read buffer since a copy of the
	     * password lives in there.
	     */
	    memset( &Client.ReadBuf, 0, sizeof Client.ReadBuf );
	    Client.BytesInReadBuffer = 0;
	    Client.ReadBytesProcessed = 0;
	    Client.LiteralBytesRemaining = 0;
	    Client.NonSyncLiteral = 0;
	    Client.MoreData = 0;
	    
	    
	    rc = cmd_login( &Client, S_UserName, S_Password, sizeof S_Password, S_Tag, LiteralFlag );
	    
	    if ( rc == 0)
		continue;
	    
	    if ( rc == 1)
	    {
		/*
		 * We caught a LOGOUT from the client.  Respond with
		 * a successful logout back to the client.
		 */
		Tag = memtok( Client.ReadBuf, EndOfLine, &Lasts );
		if ( Tag )
		{
		    strncpy( S_Tag, Tag, MAXTAGLEN - 1 );
		    S_Tag[ MAXTAGLEN - 1 ] = '\0';
		    cmd_logout( &Client, S_Tag );
		}
	    }
	    
	    /* 
	     * close the client side socket.
	     */
	    IMAPCount->CurrentClientConnections--;
	    close( Client.conn->sd );
	    return;
	    
	}
	else
	{
	    /*
	     * We got a command that we don't understand.  Treat this the
	     * same way the cyrus implementation does -- tell the client to
	     * log in first.
	     */
	    if ( Client.LiteralBytesRemaining )
	    {
		syslog( LOG_ERR, "%s: Unexpected literal specifier read from client on socket %d as part of unknown command -- disconnecting client", fn, Client.conn->sd );
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    
	    snprintf( SendBuf, BufLen, "%s BAD Please login first\r\n", Tag );
	    if ( IMAP_Write( Client.conn, SendBuf, strlen(SendBuf) ) == -1 )
	    {
		IMAPCount->CurrentClientConnections--;
		close( Client.conn->sd );
		return;
	    }
	    continue;
	    
	}
	
	
    }  /* End of infinite for loop */
    
    
    /* should never reach this code */
    IMAPCount->CurrentClientConnections--;
    close( Client.conn->sd );
    return;
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

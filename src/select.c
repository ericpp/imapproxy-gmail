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
**	select.c
**
**  Abstract:
**
**      routines to support SELECT state caching in squirrelmail-imap_proxy.
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
**      Revision 1.5  2009/10/16 14:22:38  dave64
**      Applied patch by Jose Luis Tallon to fix broken syslog call
**
**      Revision 1.4  2005/06/15 12:11:12  dgm
**      Remove unused variables.
**
**      Revision 1.3  2004/11/10 15:34:14  dgm
**      Explictly NULL terminate all strings that are the result of strncpy.
**
**      Revision 1.2  2004/03/11 15:14:06  dgm
**      Behavior of calling code when Populate_Select_Cache() fails
**      modified to not send error back to client.
**      "safe" command list updated.
**
**      Revision 1.1  2004/02/24 15:13:21  dgm
**      Initial revision
**
*/

#define _REENTRANT

#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "imapproxy.h"

/*
 * External globals
 */
extern int errno;
extern IMAPCounter_Struct *IMAPCount;

/*
 * Internal prototypes
 */
static int Send_Cached_Select_Response( ITD_Struct *, ISC_Struct *, char * );
static int Populate_Select_Cache( ITD_Struct *, ISC_Struct *, char *, char *, unsigned int );


/*
 * Function definitions.
 */

/*++
 * Function:     Handle_Select_Command
 *
 * Purpose:      The client sent a SELECT command.  Either hit the cache,
 *               or get data from the IMAP server.
 *
 * Parameters:   ptr to ITD -- client transaction descriptor
 *               ptr to ITD -- server transaction descriptor
 *               ptr to ISC -- IMAP select cache structure
 *               ptr to char -- The select command string from the client.
 *               unsigned int -- the length of the select command
 *
 * Returns:      0 - The caller should consider the entire SELECT
 *                   transaction to be complete.  This return code does not
 *                   imply successful completion.  Rather, it implies that
 *                   neither the client nor the server should be sending more
 *                   data wrt this transaction.
 *
 *               1 - This return code implies that this function was not able
 *                   to really accomplish anything useful.  The caller should
 *                   attempt to send the SELECT command by an alternate means.
 *                   The SELECT command is still in the client read buffer and
 *                   may be proxied directly to the server without the use of
 *                   this function.
 * 
 *              -1 - A hard client failure condition.  The client socket
 *                   should be shut down.
 *
 *              -2 - A hard server failure condition.  The client and server
 *                   sockets should both be shut down.
 *
 * Authors:      Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:        The SELECT command string passed into here will be the
 *               entire command, including the tag.
 *--
 */
extern int Handle_Select_Command( ITD_Struct *Client,
				  ITD_Struct *Server,
				  ISC_Struct *ISC,
				  char *SelectCmd,
				  int SelectCmdLength )
{
    char *fn = "Handle_Select_Command";
    char *Mailbox;
    char *Tag;
    char *CP;
    int rc;

    char Buf[ BUFSIZE ];

    IMAPCount->TotalSelectCommands++;
    
    /*
     * Make a local copy of the select buffer so we can chop it to hell without
     * offending the caller.
     */
    if ( SelectCmdLength >= BUFSIZE )
    {
	IMAPCount->SelectCacheMisses++;
	syslog( LOG_ERR, "%s: Length of SELECT command (%d bytes) would overflow %d byte buffer.", fn, SelectCmdLength, BUFSIZE );
	return( 1 );
    }
    
    memcpy( Buf, SelectCmd, SelectCmdLength );
    Buf[ SelectCmdLength ] = '\0';

    /*
     * NULL terminate the buffer at the end of the mailbox name
     */
    CP = memchr( (const void *)Buf, '\r', SelectCmdLength );
    if ( ! CP )
    {
	IMAPCount->SelectCacheMisses++;
	
	syslog( LOG_ERR, "%s: Sanity check failed!  SELECT command from client sd [%d] has no CRLF after it.", fn, Client->conn->sd );
	return( -1 );
    }
    *CP = '\0';

    Tag = Buf;
    CP = memchr( ( const void * )Buf, ' ', SelectCmdLength );
    
    if ( ! CP )
    {
	IMAPCount->SelectCacheMisses++;
	
	syslog( LOG_ERR, "%s: Sanity check failed!  No tokens found in SELECT command '%s' sent from client sd [%d].", fn, Buf, Client->conn->sd );
	return( 1 );
    }
    
    *CP = '\0';
    CP++;

    Mailbox = memchr( ( const void * )CP, ' ', SelectCmdLength - 
		      ( strlen( Tag ) + 1 ) );
    
    if ( ! Mailbox )
    {
	IMAPCount->SelectCacheMisses++;
	
	syslog( LOG_WARNING, "%s: Protocol error.  Client sd [%d] sent SELECT command with no mailbox name: '%s'", fn, Client->conn->sd, SelectCmd );
	snprintf( Buf, sizeof Buf - 1, "%s BAD missing required argument to SELECT command\r\n", Tag );
	if ( IMAP_Write( Client->conn, Buf, strlen( Buf ) ) == -1 )
	{
	    syslog(LOG_ERR, "%s: IMAP_Write() failed sending data to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
	    return( -1 );
	}
	return( 0 );
    }

    Mailbox++;
    
    /*
     * We have a valid SELECT command.  See if we have a cache entry that
     * isn't expired.
     */
    if ( time( 0 ) > ( ISC->ISCTime + SELECT_CACHE_EXP ) )
    {
	/*
	 * The SELECT data that's cached has expired.
	 */
	IMAPCount->SelectCacheMisses++;
	
	rc = Populate_Select_Cache( Server, ISC, Mailbox, SelectCmd, SelectCmdLength );
	if ( rc == -1 )
	{
	    return( 1 );
	}
	if ( rc == -2 )
	{
	    return( -2 );
	}
	
	rc = Send_Cached_Select_Response( Client, ISC, Tag );
	if ( rc == -2 )
	{
	    return( -1 );
	}
	if ( rc == -1 )
	{
	    snprintf( Buf, sizeof Buf - 1, "%s BAD internal proxy server error\r\n", Tag );
	    if ( IMAP_Write( Client->conn, Buf, strlen( Buf ) ) == -1 )
	    {
		syslog(LOG_ERR, "%s: IMAP_Write() failed sending data to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
		return( -1 );
	    }

	    // soft failure - we sent BAD response, so
	    // now let client decide what to do next
	    //
	    return( 0 );
	}
	
	return( 0 );
    }


    /*
     * Our data isn't expired, but is it the correct mailbox?
     */
    if ( ! strcmp( Mailbox, ISC->MailboxName ) )
    {
	/*
	 * We have the correct mailbox selected and cached already
	 */
	IMAPCount->SelectCacheHits++;
	
	rc = Send_Cached_Select_Response( Client, ISC, Tag );
	if ( rc == -2 )
	{
	    return( -1 );
	}
	if ( rc == -1 )
	{
	    snprintf( Buf, sizeof Buf - 1, "%s BAD internal proxy server error\r\n", Tag );
	    if ( IMAP_Write( Client->conn, Buf, strlen( Buf ) ) == -1 )
	    {
		syslog(LOG_ERR, "%s: IMAP_Write() failed sending data to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
		return( -1 );
	    }

	    // soft failure - we sent BAD response, so
	    // now let client decide what to do next
	    //
	    return( 0 );
	}
	
	return( 0 );
	
    }

    IMAPCount->SelectCacheMisses++;
    
    rc = Populate_Select_Cache( Server, ISC, Mailbox, SelectCmd, SelectCmdLength );
    if ( rc == -1 )
    {
	return( 1 );
    }
    if ( rc == -2 )
    {
	return( -2 );
    }
    
    rc = Send_Cached_Select_Response( Client, ISC, Tag );
    if ( rc == -2 )
    {
	return( -1 );
    }
    if ( rc == -1 )
    {
	snprintf( Buf, sizeof Buf - 1, "%s BAD internal proxy server error\r\n", Tag );
	if ( IMAP_Write( Client->conn, Buf, strlen( Buf ) ) == -1 )
	{
	    syslog(LOG_ERR, "%s: IMAP_Write() failed sending data to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
	    return( -1 );
	}

	// soft failure - we sent BAD response, so
	// now let client decide what to do next
	//
	return( 0 );
    }
    
    return( 0 );
    
}



/*++
 * Function:     Send_Cached_Select_Response
 *
 * Purpose:      Send cached SELECT server response data back to a client.
 *
 * Parameters:   ptr to ITD -- client transaction descriptor
 *               ptr to ISC -- IMAP select cache structure
 *               ptr to char -- client tag for response
 *
 * Returns:      0 on success
 *               -1 on soft failure
 *               -2 on hard failure
 *
 * Authors:      Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
static int Send_Cached_Select_Response( ITD_Struct *Client,
					ISC_Struct *ISC,
					char *Tag )
{
    char *fn = "Send_Cached_Select_Response()";
    char SendBuf[ BUFSIZE ];

    if ( IMAP_Write( Client->conn, ISC->SelectString, 
		     strlen( ISC->SelectString ) ) == -1 )
    {
	syslog( LOG_WARNING, "%s: Failed to send cached SELECT string to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
	return( -2 );
    }
    
    snprintf( SendBuf, sizeof SendBuf - 1, "%s %s", Tag, 
	      ISC->SelectStatus );
    
    if ( IMAP_Write( Client->conn, SendBuf, strlen( SendBuf ) ) == -1 )
    {
	syslog( LOG_WARNING, "%s: Failed to send cached SELECT status to client on sd [%d]: %s", fn, Client->conn->sd, strerror( errno ) );
	return( -2 );
    }

    return( 0 );
    
}




/*++
 * Function:     Populate_Select_Cache
 *
 * Purpose:      Send a SELECT command to the server and cache the response.
 *
 * Parameters:   ptr to ITD -- server transaction descriptor
 *               ptr to ISC -- the cache structure to populate
 *               ptr to char -- the mailbox name that's being selected
 *               ptr to char -- The select command string from the client.
 *               unsigned int -- the length of the select command
 *
 * Returns:      0 on success
 *               -1 on soft failure
 *               -2 on hard failure
 *
 * Authors:      Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
static int Populate_Select_Cache( ITD_Struct *Server,
				  ISC_Struct *ISC,
				  char *MailboxName,
				  char *ClientCommand,
				  unsigned int Length )
{
    char *fn = "Populate_Select_Cache()";
    int rc;
    int BytesLeftInBuffer = SELECT_BUF_SIZE;
    char *BufPtr;
    char *CP;
    char *EOS;

    rc = IMAP_Write( Server->conn, ClientCommand, Length );
    
    if ( rc == -1 )
    {
	syslog( LOG_ERR, "%s: Unable to send SELECT command to IMAP server so can't populate cache.", fn );
	return( -2 );
    }

    BufPtr = ISC->SelectString;
    
    for( ;; )
    {
	if ( Server->LiteralBytesRemaining )
	{
	    syslog( LOG_ERR, "%s: Server response to SELECT command contains unexpected literal data on sd [%d].",
	        fn, Server->conn->sd );
	    /*
	     * Must eat the literal.
	     */
	    while ( Server->LiteralBytesRemaining )
	    {
		IMAP_Literal_Read( Server );
	    }
	    
	    return( -1 );
	}
	
	rc = IMAP_Line_Read( Server );
	
	if ( ( rc == -1 ) || ( rc == 0 ) )
	{
	    syslog( LOG_WARNING, "%s: Unable to read SELECT response from IMAP server so can't populate cache.", fn );
	    return( -2 );
	}
	
	/*
	 * If it's not untagged data, we're done
	 */
	if ( Server->ReadBuf[0] != '*' )
	    break;
	
	if ( rc >= BytesLeftInBuffer ) 
	{
	    syslog( LOG_WARNING, "%s: Size of SELECT response from server exceeds max cache size of %d bytes.  Unable to cache this response.", fn, SELECT_BUF_SIZE );
	    return( -1 );
	}
	
	memcpy( (void *)BufPtr, (const void *)Server->ReadBuf, rc );
	BytesLeftInBuffer -= rc;
	BufPtr += rc;
    }
    
    /*
     * NULL terminate the buffer that contains the select response.  Note
     * that we used the >= conditional above so we'd leave one byte of
     * space for this NULL
     */
    *BufPtr = '\0';
    
    /*
     * The SELECT output string is filled in.  Now fill in the status.
     */
    CP = memchr( (const void *)Server->ReadBuf, ' ', rc );
    if ( ! CP )
    {
	syslog( LOG_ERR, "%s: Invalid response to SELECT command.  Contains no tokens.", fn );
	return( -1 );
    }
    CP++;
    
    EOS = memchr( (const void *)Server->ReadBuf, '\r', rc );
    if ( ! EOS )
    {
	syslog( LOG_ERR, "%s: Invalid response to SELECT command.  Not CRLF terminated.", fn );
	return( -2 );
    }
    
    *EOS = '\0';
    snprintf( (char *)ISC->SelectStatus, SELECT_STATUS_BUF_SIZE - 1, "%s\r\n",
	      CP );
    *EOS = '\r';

    /*
     * Update the cache time
     */
    ISC->ISCTime = time( 0 );

    strncpy( (char *)ISC->MailboxName, (const char *)MailboxName, MAXMAILBOXNAME - 1 );
    ISC->MailboxName[ MAXMAILBOXNAME - 1 ] = '\0';

    return( 0 );
    
}




/*++
 * Function:     Is_Safe_Command
 *
 * Purpose:      Determine whether a given command is "safe".  A command that
 *               is not "safe" should cause the select cache for a given
 *               mailbox to be invalidated.
 *
 * Parameters:   char ptr -- the command
 *
 * Returns:      1 if the command is safe
 *               0 if the command is not safe
 *
 * Authors:      Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
extern unsigned int Is_Safe_Command( char *Command )
{
    unsigned int i;
    
    /*
     * The safety of some of these is very questionable, particularly
     * APPEND.  Since time also invalidates the cache, hopefully the
     * contents will be accurate enough to not break stuff...
     */
    char *SafeCommands[] = 
	{
	    "CAPABILITY",
	    "NOOP",
	    "LOGOUT",
	    "STARTTLS",
	    "AUTHENTICATE",
	    "LOGIN",
	    "SELECT",
	    "EXAMINE",
	    "CREATE",
	    "DELETE",
	    "RENAME",
	    "SUBSCRIBE",
	    "UNSUBSCRIBE",
	    "LIST",
	    "LSUB",
	    "STATUS",
	    "APPEND",
	    "CHECK",
	    "SEARCH",
	    "FETCH",
	    "COPY",
	    "UID",
	    NULL
	};

    /*
     * For a list this small a simple linear search should suffice.
     */
    for ( i = 0; SafeCommands[i] != 0; i++ )
    {
	if ( ! strncasecmp( SafeCommands[i], Command,
			    strlen( SafeCommands[i] ) ) )
	{
	    return( 1 );
	}
    }
    
    return( 0 );
}



/*++
 * Function:     Invalidate_Cache_Entry
 *
 * Purpose:      Reset the cache time so the entry will not be valid
 *
 * Parameters:   ptr to ISC -- IMAP select cache structure
 *
 * Returns:      nothing
 *
 * Authors:      Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
extern void Invalidate_Cache_Entry( ISC_Struct *ISC )
{
    ISC->ISCTime = 0;
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


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
**	pimpstat.c
**
**  Abstract:
**
**	Polling Imap Mail Proxy STATistical display tool.
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
**      Revision 1.9  2006/02/17 01:42:37  dave64
**      Spelling correction (Connectsions) by Matt Selsky.
**
**      Revision 1.8  2005/06/15 12:11:36  dgm
**      Patch by Mathew Anderson to add -c flag and behavior.
**
**      Revision 1.7  2004/02/24 14:56:10  dgm
**      Added SELECT cache stuff.
**
**      Revision 1.6  2003/05/20 19:08:02  dgm
**      Comment changes only.
**
**      Revision 1.5  2003/05/15 11:33:22  dgm
**      Patch by Ken Murchison <ken@oceana.com> to clean up build process:
**      Conditionally include <sys/param.h> instead of defining MAXPATHLEN.
**
**      Revision 1.4  2003/05/13 11:41:02  dgm
**      Patches by Ken Murchison <ken@oceana.com> to clean up build process.
**
**      Revision 1.3  2003/01/27 13:49:36  dgm
**      Added patch by Frode Nordahl <frode@powertech.no> to allow
**      compilation on Linux platforms.
**
**      Revision 1.2  2002/12/17 14:24:11  dgm
**      Added support for global configuration structure.
**
**      Revision 1.1  2002/08/30 13:32:55  dgm
**      Initial revision
**
*/


#include "imapproxy.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <curses.h>
#include <time.h>
#include <strings.h>
#include <signal.h>

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#define DIGITS 11

extern WINDOW *stdscr;

static void Exit( int );
static void Handler();
static void Usage( void );


ProxyConfig_Struct PC_Struct;


/*++
 * Function:	Exit
 *
 * Purpose:	Set the terminal back to normal and then exit
 *
 * Parameters:	int -- exit code to be passed to exit()
 *
 * Returns:	nada
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
static void Exit( int ExitCode )
{
    clear();
    refresh();
    endwin();
    exit( ExitCode );
}


/*++
 * Function:	Handler
 *
 * Purpose:	SIGINT handler routine
 *
 * Parameters:	nada
 *
 * Returns:	nada
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
static void Handler()
{
    Exit( 0 );
}



int main( int argc, char *argv[] )
{
    IMAPCounter_Struct *IMAPCount;
    int fd;
    char *fn = "pimpstat";
    int i, command;
    char ccc[DIGITS+1];  /* current client conns */
    char pcc[DIGITS+1];  /* peak client conns */
    char asc[DIGITS+1];  /* active server conns */
    char psc[DIGITS+1];  /* peak server conns */
    char rsc[DIGITS+1];  /* retained (cached) server conns */
    char prsc[DIGITS+1]; /* peak retained (cached) server conns */
    char tcca[DIGITS+1]; /* total client connections accepted */
    char tcl[DIGITS+1];  /* total client logins */
    char tscc[DIGITS+1]; /* total server conns created */
    char tscr[DIGITS+1]; /* total server conns reused */
    char ssrr[DIGITS+4]; /* server socket reuse ration */
    char tsch[DIGITS+1]; /* total select cache hits */
    char tscm[DIGITS+1]; /* total select cache misses */
    float Ratio;
    char stimebuf[64];
    char ctimebuf[64];
    char *CP;
    extern char *optarg;
    extern int optind;
    char ConfigFile[ MAXPATHLEN ];
    
    ConfigFile[0] = '\0';
    
    signal( SIGINT, (void (*)()) Handler );
    
    command = 0;
    
    while (( i = getopt( argc, argv, "f:ch" ) ) != EOF )
    {
	
        switch( i )
        {
	    
        case 'f':
            /* user specified a config filename */
            strncpy( ConfigFile, optarg, sizeof ConfigFile -1 );
            break;
    
	case 'c':
	    /* user wants output via command line */
	    command=1;
	    break;
	    
        case 'h':
            Usage();
            exit( 0 );
	    
        case '?':
            Usage();
	    
            exit( 1 );
	    
        }
	
    }
    
    if ( ! ConfigFile[0] )
    {
	
        strncpy( ConfigFile, DEFAULT_CONFIG_FILE, sizeof ConfigFile -1 );
    }

    SetConfigOptions( ConfigFile );
        
    fd = open( PC_Struct.stat_filename, O_RDONLY );
    if ( fd == -1 )
    {
        printf("%s: open() failed for '%s': %s -- Exiting.\n", fn, 
               PC_Struct.stat_filename, strerror( errno ) ); 
        exit( 1 );
    }
    

    IMAPCount = ( IMAPCounter_Struct *)mmap( 0, sizeof( IMAPCounter_Struct ),
                                             PROT_READ, MAP_SHARED, fd, 0 );
    
    if ( IMAPCount == MAP_FAILED )
    {
        printf("%s: mmap() failed: %s -- Exiting.\n", fn, strerror( errno ) );
        exit( 1 );
    }
    

    if ( command == 0 )
    {
	stdscr = initscr();

	if ( !stdscr )
	{
	    printf("%s: failed to initialize screen -- exiting.\n", fn );
	    exit( 1 );
	}
	
	border( 0, 0, 0, 0, 0, 0, 0, 0 );
	mvaddstr( 2, 8, "Server Start Time:" );
	mvaddstr( 3, 2, "Last Counter Reset Time:" );
	mvaddstr( 5, 2, "CLIENT CONNECTIONS" );
	mvaddstr( 7, 5, "current:" );
	mvaddstr( 7, 40, "peak:" );
	mvaddstr( 9, 2, "ACTIVE SERVER CONNECTIONS" );
	mvaddstr( 11, 5, "current:" );
	mvaddstr( 11, 40, "peak:" );
	mvaddstr( 13, 2, "CACHED SERVER CONNECTIONS" );
	mvaddstr( 15, 5, "current:");
	mvaddstr( 15, 40, "peak:" );
	mvaddstr( 17, 2, "CONNECTION TOTALS" );
	mvaddstr( 19, 5, "client connections accepted:" );
	mvaddstr( 20, 5, "client logins:" );
	mvaddstr( 21, 5, "server connections created:" );
	mvaddstr( 22, 5, "server connection reuses:" );
	mvaddstr( 23, 5, "client login to server login ratio:" );
	if ( PC_Struct.enable_select_cache )
	{
	    mvaddstr( 25, 2, "SELECT CACHE TOTALS" );
	    mvaddstr( 27, 5, "hit:" );
	    mvaddstr( 27, 40, "miss:" );
	}
	else
	{
	    mvaddstr( 25, 2, "SELECT CACHE NOT ENABLED" );
	}
	
	mvaddstr( 29, 2, "CTRL-C to quit." );
	
	for ( ; ; )
	{
	    /*
	     * I don't know crap about curses.  There's prolly an easy way to 
	     * accomplish this, but I don't know how.  Basically we have to
	     * turn all of our numbers into strings so curses can display them.
	     * I'd guess there's a printf equivalent in curses, but I dunno.
	     */
	    
	    if ( IMAPCount->TotalServerConnectionsCreated == 0 )
	    {
		snprintf( ssrr, DIGITS + 3, "          N/A" );
	    }
	    else
	    {
		Ratio = (float)IMAPCount->TotalClientLogins /
		    (float)IMAPCount->TotalServerConnectionsCreated;
		snprintf( ssrr, DIGITS + 3, "%9.2f : 1", Ratio );
	    }
	    
	    /*
	     * ctime is putting a \n at the end of the string and that's
	     * making curses do goofy stuff that I don't understand.  Rather
	     * than figure out why it's breaking curses, I'm just going to
	     * copy ctime's strings into my own buffers and get rid of the
	     * \n.
	     */
	    strncpy( stimebuf, ctime( &IMAPCount->StartTime ),
		     sizeof stimebuf - 1 );
	    strncpy( ctimebuf, ctime( &IMAPCount->CountTime ),
		     sizeof ctimebuf - 1 );
	    
	    CP = strrchr( stimebuf, '\n' );
	    if (CP)
		*CP = '\0';
	    
	    CP = strrchr( ctimebuf, '\n' );
	    if (CP)
		*CP ='\0';
	    
	    snprintf( ccc, DIGITS, "%9d", IMAPCount->CurrentClientConnections );
	    snprintf( pcc, DIGITS, "%9d", IMAPCount->PeakClientConnections );
	    snprintf( asc, DIGITS, "%9d", IMAPCount->InUseServerConnections );
	    snprintf( psc, DIGITS, "%9d", IMAPCount->PeakInUseServerConnections );
	    snprintf( rsc, DIGITS, "%9d", IMAPCount->RetainedServerConnections );
	    snprintf( prsc, DIGITS, "%9d", IMAPCount->PeakRetainedServerConnections );
	    snprintf( tcca, DIGITS, "%9d", IMAPCount->TotalClientConnectionsAccepted );
	    snprintf( tcl, DIGITS, "%9d", IMAPCount->TotalClientLogins );
	    snprintf( tscr, DIGITS, "%9d", IMAPCount->TotalServerConnectionsReused );
	    snprintf( tscc, DIGITS, "%9d", IMAPCount->TotalServerConnectionsCreated );
	    snprintf( tsch, DIGITS, "%9d", IMAPCount->SelectCacheHits );
	    snprintf( tscm, DIGITS, "%9d", IMAPCount->SelectCacheMisses );
	    
	    mvaddstr( 2, 31, stimebuf );
	    mvaddstr( 3, 31, ctimebuf );
	    mvaddstr( 7, 14, ccc );
	    mvaddstr( 7, 46, pcc );
	    mvaddstr( 11, 14, asc );
	    mvaddstr( 11, 46, psc );
	    mvaddstr( 15, 14, rsc );
	    mvaddstr( 15, 46, prsc );
	    mvaddstr( 19, 46, tcca );
	    mvaddstr( 20, 46, tcl );
	    mvaddstr( 21, 46, tscc );
	    mvaddstr( 22, 46, tscr );
	    mvaddstr( 23, 42, ssrr );
	    if ( PC_Struct.enable_select_cache )
	    {
		mvaddstr( 27, 14, tsch );
		mvaddstr( 27, 46, tscm );
	    }
	    
	    refresh();
	    
	    sleep( 1 );
	}
	
    }
    else
    {
	/*
	 * We only get here if command is non-zero.
	 */
	printf( " %d Current Client Connections\n %d Peak Client Connections\n %d In Use Connections\n %d Peak In Use Connections\n %d Retained Server Connections\n %d Peak Retained Server Connections\n %d Total Client Connections\n %d Total Client Logins\n %d Total Reused Connections\n %d Total Created Connections\n %d Cache Hits\n %d Cache Misses\n", IMAPCount->CurrentClientConnections,
		IMAPCount->PeakClientConnections, 
		IMAPCount->InUseServerConnections,
		IMAPCount->PeakInUseServerConnections,
		IMAPCount->RetainedServerConnections,
		IMAPCount->PeakRetainedServerConnections,
		IMAPCount->TotalClientConnectionsAccepted,
		IMAPCount->TotalClientLogins,
		IMAPCount->TotalServerConnectionsReused,
		IMAPCount->TotalServerConnectionsCreated, 
		IMAPCount->SelectCacheHits,
		IMAPCount->SelectCacheMisses );

	exit( 0 );
    }
}



/*++
 * Function:    Usage
 *
 * Purpose:     Display a usage string to stdout
 *
 * Parameters:  None.
 *
 * Returns:     nada
 * 
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 * 
 * Notes:
 *--
 */
void Usage( void )
{
    printf( "Usage: pimpstat [-f config filename] [-h] [-c]\n" );
    printf( " -c is for simple command line output format instead of curses.\n" );
    
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



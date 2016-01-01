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
**      logging.c
**
**  Abstract:
**
**      Routines to allow syslog levels and facilities to be configurable.
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
**      Revision 1.4  2005/06/15 12:10:39  dgm
**      Include string.h.
**
**      Revision 1.3  2004/11/10 15:30:17  dgm
**      Explictly NULL terminate all strings that are the result
**      of strncpy.
**
**      Revision 1.2  2003/05/20 19:01:49  dgm
**      Comment changes only.
**
**      Revision 1.1  2003/04/16 12:14:31  dgm
**      Initial revision
**
*/

#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include "imapproxy.h"

#define _REENTRANT
#define NUM_OF_FACILITIES      LOG_NFACILITIES
#define MAX_FACILITY_STRINGLEN 64
#define NUM_OF_PRIORITIES      9
#define MAX_PRIORITY_STRINGLEN 64

struct SyslogFacilityMap_Struct
{
    char FacilityString[ MAX_FACILITY_STRINGLEN ];
    int FacilityValue;
};

struct SyslogPriorityMap_Struct
{
    char PriorityString[ MAX_PRIORITY_STRINGLEN ];
    int PriorityValue;
};


struct SyslogFacilityMap_Struct SyslogFacilityTable[ NUM_OF_FACILITIES ];
struct SyslogPriorityMap_Struct SyslogPriorityTable[ NUM_OF_PRIORITIES ];


/*
 * macro to populate the facility map.
 */
#define ADD_TO_FACILITY_MAP( FACILITY, INDEX ) \
        if ( INDEX >= NUM_OF_FACILITIES ) \
        { \
           syslog( LOG_ERR, "Syslog facility map overflow!  Exiting." ); \
           exit( 1 ); \
        } \
        strncpy( SyslogFacilityTable[ INDEX ].FacilityString, #FACILITY, MAX_FACILITY_STRINGLEN - 1 ); \
        SyslogFacilityTable[ INDEX ].FacilityString[ MAX_FACILITY_STRINGLEN - 1 ] = '\0'; \
        SyslogFacilityTable[ INDEX ].FacilityValue = FACILITY; \
        INDEX++;


/*
 * macro to populate the above priority map.
 */
#define ADD_TO_PRIORITY_MAP( PRIORITY, INDEX ) \
        if ( INDEX >= NUM_OF_PRIORITIES ) \
        { \
           syslog( LOG_ERR, "Syslog priority map overflow!  Exiting." ); \
           exit( 1 ); \
        } \
        strncpy( SyslogPriorityTable[ INDEX ].PriorityString, #PRIORITY, MAX_PRIORITY_STRINGLEN - 1 ); \
        SyslogPriorityTable[ INDEX ].PriorityString[ MAX_PRIORITY_STRINGLEN - 1 ] = '\0'; \
        SyslogPriorityTable[ INDEX ].PriorityValue = PRIORITY; \
        INDEX++;


/*
 * External globals
 */
extern ProxyConfig_Struct PC_Struct;


/*++
 * Function:     SetLogOptions
 *
 * Purpose:      Set the syslog logging facility and priority mask based o
 *               options from the proxy configfile.
 *
 * Parameters:   void
 *
 * Returns:      nada.  Exits on any failure.
 *
 * Authors:      Dave McMurtrie  <davemcmurtrie@hotmail.com>
 *
 * Notes:        If nothing is set in the configfile, it will default
 *               to LOG_MAIL facility and no logmask.
 *               This function relies on the fact that
 *               SetConfigOptions() has already been called and the global
 *               ProxyConfig_Struct "PC_Struct" is populated.
 *--
 */
extern void SetLogOptions( void )
{
    unsigned int index;
    int facility;
    int prioritymask;
    
    index = 0;
    facility = -1;
    prioritymask = -1;
	
    ADD_TO_FACILITY_MAP( LOG_USER, index );
    ADD_TO_FACILITY_MAP( LOG_MAIL, index );
    ADD_TO_FACILITY_MAP( LOG_DAEMON, index );
    ADD_TO_FACILITY_MAP( LOG_AUTH, index );
    ADD_TO_FACILITY_MAP( LOG_LPR, index );
    ADD_TO_FACILITY_MAP( LOG_NEWS, index );
    ADD_TO_FACILITY_MAP( LOG_UUCP, index );
    ADD_TO_FACILITY_MAP( LOG_CRON, index );
    ADD_TO_FACILITY_MAP( LOG_LOCAL0, index );
    ADD_TO_FACILITY_MAP( LOG_LOCAL1, index );
    ADD_TO_FACILITY_MAP( LOG_LOCAL2, index );
    ADD_TO_FACILITY_MAP( LOG_LOCAL3, index );
    ADD_TO_FACILITY_MAP( LOG_LOCAL4, index );
    ADD_TO_FACILITY_MAP( LOG_LOCAL5, index );
    ADD_TO_FACILITY_MAP( LOG_LOCAL6, index );
    ADD_TO_FACILITY_MAP( LOG_LOCAL7, index );
    
    if ( index >= NUM_OF_FACILITIES )
    {
	syslog( LOG_ERR, "Syslog facility map overflow!  Exiting." ); 
	exit( 1 ); 
    }

    SyslogFacilityTable[ index ].FacilityString[0] = '\0';

    index = 0;
    
    ADD_TO_PRIORITY_MAP( LOG_EMERG, index );
    ADD_TO_PRIORITY_MAP( LOG_ALERT, index );
    ADD_TO_PRIORITY_MAP( LOG_CRIT, index );
    ADD_TO_PRIORITY_MAP( LOG_ERR, index );
    ADD_TO_PRIORITY_MAP( LOG_WARNING, index );
    ADD_TO_PRIORITY_MAP( LOG_NOTICE, index );
    ADD_TO_PRIORITY_MAP( LOG_INFO, index );
    ADD_TO_PRIORITY_MAP( LOG_DEBUG, index );
    
    if ( index >= NUM_OF_PRIORITIES )
    {
	syslog( LOG_ERR, "Syslog priority map overflow!  Exiting." ); 
	exit( 1 ); 
    }

    SyslogPriorityTable[ index ].PriorityString[0] = '\0';


    /*
     * First set the logging facility.
     */
    if ( !PC_Struct.syslog_facility )
    {
	syslog( LOG_INFO, "syslog_facility not specified.  Defaulting to LOG_MAIL." );
	facility = LOG_MAIL;
    }
    else
    {
	for ( index = 0; index < NUM_OF_FACILITIES; index++ )
	{
	    if ( SyslogFacilityTable[ index ].FacilityString[0] == '\0' )
		break;
	    
	    if ( !strcmp( SyslogFacilityTable[ index ].FacilityString, PC_Struct.syslog_facility ) )
	    {
		facility = SyslogFacilityTable[ index ].FacilityValue;
		syslog( LOG_INFO, "Using syslog facility '%s' for logging.", PC_Struct.syslog_facility );
		break;
	    }
	    
	}
    }
    
    if ( facility == -1 )
    {
	facility = LOG_MAIL;
	syslog( LOG_INFO, "Unknown syslog facility '%s' specified.  Defaulting to LOG_MAIL.", PC_Struct.syslog_facility );
    }
    
    openlog( PGM, LOG_PID, facility );
    

    /*
     * Now do essentially the same for the priority mask
     */
    if ( !PC_Struct.syslog_prioritymask )
    {
	syslog( LOG_INFO, "No syslog priority mask specified." );
	return;
    }
    
    for ( index = 0; index < NUM_OF_PRIORITIES; index++ )
    {
	if ( SyslogPriorityTable[ index ].PriorityString[0] == '\0' )
	    break;
	
	if ( !strcmp( SyslogPriorityTable[ index ].PriorityString, PC_Struct.syslog_prioritymask ) )
	{
	    prioritymask = SyslogPriorityTable[ index ].PriorityValue;
	    syslog( LOG_INFO, "Masking syslog priority up to %s.", SyslogPriorityTable[ index ].PriorityString );
	    break;
	}
    }
    
    if ( prioritymask == -1 )
    {
	syslog( LOG_INFO, "Unknown syslog priority mask '%s' specified.  Not masking.", PC_Struct.syslog_prioritymask );
	return;
    }
    
    setlogmask( LOG_UPTO( prioritymask ) );
    
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
	    
	    
	
    
    
    
    

    

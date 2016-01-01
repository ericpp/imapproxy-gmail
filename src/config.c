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
**	config.c
**
**  Abstract:
**
**	Routines for parsing a config file and setting global configuration
**	options.
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
**      Revision 1.18  2009/10/16 14:34:49  dave64
**      Applied patch by Jose Luis Tallon to improve server connect retry logic.
**
**      Revision 1.17  2009/10/16 14:29:03  dave64
**      Applied patch by Jose Luis Tallon to allow for default config options.
**
**      Revision 1.16  2007/05/31 12:08:32  dave64
**      Applied ipv6 patch by Antonio Querubin.
**
**      Revision 1.15  2005/07/06 12:17:44  dgm
**      Add enable_admin_commands to ConfigTable.
**
**      Revision 1.14  2005/06/15 12:12:26  dgm
**      Patch by Dave Steinberg and Jarno Huuskonen to add chroot_directory
**      config option.
**
**      Revision 1.13  2005/01/12 17:49:51  dgm
**      Applied patch by David Lancaster to provide force_tls config
**      option.
**
**      Revision 1.12  2004/11/10 15:26:25  dgm
**      Explictly NULL terminate all strings that are the result of an strncpy.
**
**      Revision 1.11  2004/10/11 18:01:29  dgm
**      Added foreground mode configuration option.
**
**      Revision 1.10  2004/02/24 14:57:47  dgm
**      Added new config option 'enable_select_cache'.
**
**      Revision 1.9  2003/11/14 15:03:58  dgm
**      Patch by Geoffrey Hort <g.hort@unsw.edu.au> to allow
**      configurable listen address.
**
**      Revision 1.8  2003/10/23 06:18:58  dgm
**      Fixed bug in SetBooleanValue doing upcase of Value.
**
**      Revision 1.7  2003/10/09 12:36:08  dgm
**      Added the ability to set boolean configuration options.
**
**      Revision 1.6  2003/05/20 18:42:04  dgm
**      comment changes only.
**
**      Revision 1.5  2003/05/06 12:10:37  dgm
**      Applied patches by Ken Murchison to include additional config options
**      for SSL support.
**
**      Revision 1.4  2003/04/16 12:13:34  dgm
**      Added commodore logo ascii-art comment at the end.
**      Added support for syslog configuration options.
**
**      Revision 1.3  2003/02/17 14:08:42  dgm
**      added an fclose() that I forgot.
**
**      Revision 1.2  2003/01/27 13:59:15  dgm
**      Patch by Gary Mills <mills@cc.UManitoba.CA> to allow compilation
**      using Sun's cc instead of gcc.
**
**      Revision 1.1  2002/12/17 14:26:49  dgm
**      Initial revision
**
*/


#define _REENTRANT
#define MAX_KEYWORD_LEN 128

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "common.h"
#include "imapproxy.h"


/*
 * External globals
 */
extern ProxyConfig_Struct PC_Struct;


/*
 * Internal prototypes
 */
static void SetStringValue( char *, char **, unsigned int );
static void SetNumericValue( char *, int *, unsigned int );
static void SetBooleanValue( char *, unsigned int *, unsigned int );

/*
 * An array of Config_Structs will need to be allocated, one for
 * every possible keyword/value combination (plus a NULL).  Note that
 * I declare an array of 100, meaning that there's a hard limit of 99
 * possible config values right now.  Currently, there are only 9 in use.
 */
struct Config_Struct
{
    char Keyword[MAX_KEYWORD_LEN]; /* The configuration keyword */
    void (*(SetFunction))();       /* ptr to function used to set the value */
    void *StorageAddress;          /* address to store the value */
};

struct Config_Struct ConfigTable[ 100 ];

/*
 * Macro to populate the above ConfigTable
 */
#define ADD_TO_TABLE( KEYWORD, SETFUNCTION, STA, INDEX ) \
        strncpy( ConfigTable[ INDEX ].Keyword, KEYWORD, MAX_KEYWORD_LEN -1 ); \
        ConfigTable[ INDEX ].Keyword[ MAX_KEYWORD_LEN - 1 ] = '\0'; \
        ConfigTable[ INDEX ].SetFunction = SETFUNCTION; \
        ConfigTable[ INDEX ].StorageAddress = STA; \
        INDEX++;





/*++
 * Function:	SetStringValue
 *
 * Purpose:	Common routine to assign string values in the config
 *		options struct.
 *
 * Parameters:  ptr to string from config file
 *              ptr to char ptr for dynamically allocated storage for string.
 *              int -- line of config file where the string was read from.
 *
 * Returns:     nada -- exit()s on errors.
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
static void SetStringValue( char *String, 
			    char **SavedString, 
			    unsigned int linenum )
{
    char *fn = "SetStringValue()";
    unsigned int Size;
    
    Size = strlen( String ) + 1;
    
    /*
     * Do some reasonable bounds checking before we malloc()
     */
    if ( ( Size < 1 ) || ( Size > 4096 ) )
    {
	syslog( LOG_ERR, "%s: Length of string value at line %d of config file is not within size boundaries -- Exiting.", fn, linenum );
	exit( 1 );
    }
    
    *SavedString = malloc( Size );
    
    if ( ! *SavedString )
    {
	syslog( LOG_ERR, "%s: malloc() failed: %s -- Exiting.", fn,
		strerror( errno ) );
	exit( 1 );
    }
    
    memcpy( *SavedString, String, Size );
    
    return;
}


    


/*++
 * Function:    SetNumericValue
 *
 * Purpose:     Common routine to convert an ascii string to a numeric value
 *              and set a config value accordingly.
 *
 * Parameters:  ptr to the string value to convert. 
 *              ptr to int.  (where to store the converted value)
 *              int -- line of config file where the string was read from.
 *
 * Returns:     nada -- exit()s on failure.
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:
 *--
 */
static void SetNumericValue( char *StringValue, 
			     int *Value, 
			     unsigned int linenum )
{
    char *fn = "SetNumericValue()";

    /*
     * Need to generalize this routine.  atoi() seems to only set errno
     * on Solaris, making this very platform specific.
     */
    *Value = atoi( (const char *)StringValue );

    if ( ( ! *Value ) &&
	 ( errno == EINVAL ) )
    {
	syslog( LOG_ERR, "%s: numeric value specified at line %d of config file is invalid -- Exiting.", fn, linenum );
	exit( 1 );
    }

    return;
}




/*++
 * Function:    SetBooleanValue
 *
 * Purpose:     Common routine to assign true/false (or yes/no) values in
 *              the config options struct. 
 *
 * Parameters:  ptr to string value from configfile (yes, no, true, false)
 *              ptr to unsigned int -- where to store the boolean value (1/0)
 *              unsigned int -- Config file line number
 *
 * Returns:     nada -- exit()s on errors.
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:       This function is not case sensitive.
 *              It will parse any of y, yes, true and store it as 1.
 *              It will parse any of n, no, false and store it as 0.
 *
 *              Major note -- the Value passed into here will be upcased.
 *--
 */
static void SetBooleanValue( char *Value,
			     unsigned int *StoredValue,
			     unsigned int linenum )
{
    char *fn = "SetBooleanValue()";
    char *CP;
    
    /*
     * Upcase for ease of comparison
     */
    CP = Value;
    while( *CP )
    {
	*CP = toupper( *CP );
	CP++;
    }
    
    if ( ( ( Value[0] == 'Y' ) && ( Value[1] == '\0' ) ) ||
	 ( ( Value[0] == 'Y' ) && ( Value[1] == 'E' ) && ( Value[2] == 'S' ) ) )
    {
	*StoredValue = 1;
	return;
    }
    
    if ( ( ( Value[0] == 'N' ) && ( Value[1] == '\0' ) ) ||
	 ( ( Value[0] == 'N' ) && ( Value[1] == 'O' ) ) )
    {
	*StoredValue = 0;
	return;
    }

    if ( !strcmp( "TRUE", Value ) )
    {
	*StoredValue = 1;
	return;
    }
    
    if ( !strcmp( "FALSE", Value ) )
    {
	*StoredValue = 0;
	return;
    }
    
    syslog( LOG_WARNING, "%s: Invalid boolean value '%s' specified at line %d of config file.  Defaulting to FALSE.", fn, Value, linenum );
    *StoredValue = 0;
    return;
}


/*++
 * Function:	SetDefaultConfigValues
 *
 * Purpose:	Set global configuration default values
 *
 * Parameters:	pointer to global config struct
 *
 * Returns:	nada.
 *
 * Authors:	Jose Luis Tallon <jltallon@adv-solutions.net>
 *--
 */
void SetDefaultConfigValues(ProxyConfig_Struct *PC_Struct)
{
    PC_Struct->server_connect_retries = DEFAULT_SERVER_CONNECT_RETRIES;
    PC_Struct->server_connect_delay = DEFAULT_SERVER_CONNECT_DELAY;

    return;
}

/*++
 * Function:	SetConfigOptions
 *
 * Purpose:	Set global configuration options by reading and parsing
 *		the configuration file.
 *
 * Parameters:	char pointer to config filename path.
 *
 * Returns:	nada.  exit()s on any error.
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:       Sets values in global ProxyConfig_Struct PC_Struct.
 *--
 */
extern void SetConfigOptions( char *ConfigFile )
{
    FILE *FP;
    char *fn = "SetConfigOptions()";
    char Buffer[1024];
    unsigned int LineNumber;
    unsigned int index;
    unsigned int i;
    char *CP;
    char *Keyword;
    char *Value;
   
    index = LineNumber = 0;

    /*
     * initialize the proxy config struct
     */
    memset( &PC_Struct, 0, sizeof PC_Struct );
    

    /*
     * Build our config option table.
     */
    ADD_TO_TABLE( "server_hostname", SetStringValue, 
		  &PC_Struct.server_hostname, index );

    ADD_TO_TABLE( "listen_port", SetStringValue, 
		  &PC_Struct.listen_port, index );

    ADD_TO_TABLE( "listen_address", SetStringValue,
		  &PC_Struct.listen_addr, index );

    ADD_TO_TABLE( "server_port", SetStringValue, 
		  &PC_Struct.server_port, index );

    ADD_TO_TABLE( "connect_retries", SetNumericValue,
		  &PC_Struct.server_connect_retries, index );
    ADD_TO_TABLE( "connect_delay", SetNumericValue,
		  &PC_Struct.server_connect_delay, index );

    ADD_TO_TABLE( "cache_size", SetNumericValue, 
		  &PC_Struct.cache_size, index );

    ADD_TO_TABLE( "cache_expiration_time", SetNumericValue, 
		  &PC_Struct.cache_expiration_time, index );

    ADD_TO_TABLE( "preauth_command", SetStringValue,
		  &PC_Struct.preauth_command, index );

    ADD_TO_TABLE( "auth_sasl_plain_username", SetStringValue,
		  &PC_Struct.auth_sasl_plain_username, index );
    
    ADD_TO_TABLE( "auth_sasl_plain_password", SetStringValue,
		  &PC_Struct.auth_sasl_plain_password, index );

    ADD_TO_TABLE( "auth_shared_secret", SetStringValue,
		  &PC_Struct.auth_shared_secret, index);

    ADD_TO_TABLE( "proc_username", SetStringValue,
		  &PC_Struct.proc_username, index );
    
    ADD_TO_TABLE( "proc_groupname", SetStringValue,
		  &PC_Struct.proc_groupname, index );
    
    ADD_TO_TABLE( "stat_filename", SetStringValue,
		  &PC_Struct.stat_filename, index );

    ADD_TO_TABLE( "syslog_facility", SetStringValue,
		  &PC_Struct.syslog_facility, index );
    
    ADD_TO_TABLE( "protocol_log_filename", SetStringValue,
		  &PC_Struct.protocol_log_filename, index );

    ADD_TO_TABLE( "syslog_prioritymask", SetStringValue,
		  &PC_Struct.syslog_prioritymask, index );
    
    ADD_TO_TABLE( "tls_ca_file", SetStringValue,
		  &PC_Struct.tls_ca_file, index );
    
    ADD_TO_TABLE( "tls_ca_path", SetStringValue,
		  &PC_Struct.tls_ca_path, index );
    
    ADD_TO_TABLE( "tls_cert_file", SetStringValue,
		  &PC_Struct.tls_cert_file, index );
    
    ADD_TO_TABLE( "tls_key_file", SetStringValue,
		  &PC_Struct.tls_key_file, index );

    ADD_TO_TABLE( "tls_ciphers", SetStringValue,
		  &PC_Struct.tls_ciphers, index );

    ADD_TO_TABLE( "tls_verify_server", SetBooleanValue,
		  &PC_Struct.tls_verify_server, index );

    ADD_TO_TABLE( "tls_no_tlsv1", SetBooleanValue,
		  &PC_Struct.tls_no_tlsv1, index );

    ADD_TO_TABLE( "tls_no_tlsv1.1", SetBooleanValue,
		  &PC_Struct.tls_no_tlsv1_1, index );

    ADD_TO_TABLE( "tls_no_tlsv1.2", SetBooleanValue,
		  &PC_Struct.tls_no_tlsv1_2, index );

    ADD_TO_TABLE( "send_tcp_keepalives", SetBooleanValue,
		  &PC_Struct.send_tcp_keepalives, index );

    ADD_TO_TABLE( "chroot_directory", SetStringValue,
		  &PC_Struct.chroot_directory, index );

    ADD_TO_TABLE( "enable_select_cache", SetBooleanValue,
		  &PC_Struct.enable_select_cache, index );

    ADD_TO_TABLE( "foreground_mode", SetBooleanValue,
		  &PC_Struct.foreground_mode, index );

    ADD_TO_TABLE( "force_tls", SetBooleanValue,
		  &PC_Struct.force_tls, index );

    ADD_TO_TABLE( "enable_admin_commands", SetBooleanValue,
		  &PC_Struct.enable_admin_commands, index );
    
    ConfigTable[index].Keyword[0] = '\0';
    
    FP = fopen( ConfigFile, "r" );
    
    if ( !FP )
    {
	syslog(LOG_ERR, "%s: Unable to open config file '%s': %s -- Exiting",
	       fn, ConfigFile, strerror( errno ) );
	exit( 1 );
    }
    
    for ( ;; )
    {
	if ( !fgets( Buffer, sizeof Buffer, FP ) )
	    break;
	    
	LineNumber++;
	    
	/*
	 * Nullify comments, and CRLFs
	 */
	CP = strchr( Buffer, '#' );
	if ( CP ) *CP = 0;
	
	CP = strchr( Buffer, '\n' );
	if ( CP ) *CP = 0;
	
	CP = strchr( Buffer, '\r' );
	if ( CP ) *CP = 0;
	
	/*
	 * Any line that started with a comment or CRLF, we'll
	 * skip.
	 */
	if ( !strlen( Buffer ) )
	    continue;
	
	CP = strtok( Buffer, " " );
	if ( !CP )
	{
	    syslog(LOG_ERR, "%s: parse error reading config file at line %d.  Exiting.", fn, LineNumber );
	    exit( 1 );
	}
	
	Keyword = CP;
	
	CP = strtok( NULL, " " );
	
	if ( !CP )
	{
	    syslog(LOG_ERR, "%s: parse error reading config file at line %d.  Exiting.", fn, LineNumber );
	    exit( 1 );
	}
	
	Value = CP;

	// we don't just want the next token, we want the rest of the line
	// (put back the space that strtok() changed into a null character)
	//
	Value[ strlen( Value ) ] = ' ';

	// however, we then have to be careful to remove trailing whitespace
	//
	i = strlen( Value ) - 1;
	while ( ( Value[ i ] == ' ' )
	     || ( Value[ i ] == '\t' )
	     || ( Value[ i ] == '\r' )
	     || ( Value[ i ] == '\n' ) )
	{
	    i--;
	}
	if ( i < ( strlen( Value ) - 1 ) )
	    Value[ i + 1 ] = '\0';
	
	for (i = 0; ConfigTable[i].Keyword[0] != '\0'; i++ )
	{
	    if ( ! strcasecmp( (const char *)Keyword, ConfigTable[i].Keyword ) )
	    {
		( ConfigTable[i].SetFunction )( Value, 
						ConfigTable[i].StorageAddress,
						LineNumber );
		break;
	    }
	    
	}
	
	/*
	 * If we get here and we're at our NULL value at the end of our
	 * keyword array, we cycled through the entire array and never
	 * matched any keyword.
	 */
	if ( ! ConfigTable[i].Keyword )
	{
	    syslog( LOG_ERR, "%s: unknown keyword '%s' found at line %d of config file -- Exiting.", fn, Keyword, LineNumber );
	    exit( 1 );
	}
	
    }

    fclose( FP );
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

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
**	main.c
**
**  Abstract:
**
**	The main source module for the IMAP proxy server.  This source
**	module contains routines to handle server initialization
**	and the main server loop.
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
**      Revision 1.40  2009/10/16 14:34:16  dave64
**      Applied patch by Jose Luis Tallon to improve server connect retry logic.
**
**      Revision 1.39  2009/10/16 14:25:31  dave64
**      Applied patch by Jose Luis Tallon to allow for default config options.
**
**      Revision 1.38  2009/10/16 14:09:45  dave64
**      applied patch by Jose Luis Tallon to fix compiler warnings
**
**      Revision 1.37  2009/01/12 13:13:01  dave64
**      Applied patch by Michael Slusarz to add XIMAPPROXY capability.
**
**      Revision 1.36  2008/10/20 13:47:49  dave64
**      Applied patch by Michael M. Slusarz to add XIMAPPROXY
**      to capability string returned by imapproxy to clients.
**
**      Revision 1.35  2008/03/05 13:12:07  dave64
**      Applied patch by Noel B to disable IDLE capability.
**
**	Revision 1.34  2007/11/15 11:14:16  dave64
**	Patch by Jose Luis Tallón to add pidfile support and
**	enhance daemon behavior.
**
**	Revision 1.33  2007/05/31 12:10:59  dave64
**	Applied ipv6 patch by Antonio Querubin.
**
**	Revision 1.32  2007/05/31 11:46:42  dave64
**	Applied OpenSSL threads patch by Jan Grant.
**
**	Revision 1.31  2006/10/03 12:13:09  dave64
**	Patch by Matt Selsky to log ssl peer verify at debug level instead
**	of err level.
**
**	Revision 1.30  2006/04/13 12:39:15  dave64
**	Patch by Ramiro Morales to prevent bad file descriptor error
**	on startup.
**
**	Revision 1.29  2006/02/16 18:43:42  dave64
**	Added IMAP_PROXY_VERSION string to startup log message.
**
**	Revision 1.28  2006/02/16 18:30:14  dave64
**	Fixed string format bug (Debian DSA 852-1) found by Steve Kemp.
**
**	Revision 1.27  2005/07/06 11:49:40  dgm
**	Add support for enable_admin_commands config option.
**
**	Revision 1.26  2005/06/22 14:39:04  dgm
**	Made initial imap server connection and DNS lookup more robust.
**
**	Revision 1.25  2005/06/15 12:05:25  dgm
**	Included config.h.
**
**	Revision 1.24  2005/06/07 12:08:44  dgm
**	Added missing include directives to avoid implicit declarations.
**
**	Revision 1.23  2005/01/12 17:50:45  dgm
**	Applied patch by David Lancaster to provide force_tls
**	config option.
**
**	Revision 1.22  2005/01/12 17:11:30  dgm
**	Patch by Joseph Tam to prevent SIGSEGV in RAND_egd().
**
**	Revision 1.21  2004/11/10 15:32:02  dgm
**	Explictly NULL terminate all strings that are the result
**	of strncpy.  Also enforce checking of LiteralBytesRemaining
**	after any calls to IMAP_Line_Read.
**
**	Revision 1.20  2004/10/11 18:23:19  dgm
**	Added foreground_mode option.
**
**	Revision 1.19  2004/02/24 15:17:20  dgm
**	Added ParseBannerAndCapability() function to allow for
**	parsing the banner string and capability strings.  Can
**	now handle capability string in explicit capability
**	response, or as part of the banner string.
**
**	Added SELECT caching stuff.
**
**	Revision 1.18  2003/11/14 14:59:44  dgm
**	Applied patches by Geoffrey Hort <g.hort@unsw.edu.au> to allow
**	configurable listen address.  Discard token "SASL-IR" if server
**	advertises it as a capability (previously, we were discarding
**	"SASL").  Reference Revision 1.17 of this source module.
**
**	Revision 1.17  2003/10/10 15:07:02  dgm
**	Patch by Ken Murchison <ken@oceana.com> applied.  Discard "SASL"
**	capability if advertised by the server.  This is a new extension
**	that will be supported in Cyrus v2.2.2.
**
**	Revision 1.16  2003/10/09 13:03:52  dgm
**	Added configurable tcp keepalive support.  Added retry logic for
**	initial socket connection to imap server in SetBannerAndCapability()
**	so it won't just fatally exit on ECONNREFUSED (submitted by Gary
**	Mills <mills@cc.UManitoba.CA>).
**
**	Revision 1.15  2003/07/14 16:39:58  dgm
**	Applied patch by William Yodlowsky <wyodlows@andromeda.rutgers.edu>
**	to allow TLS to work on machines without /dev/random.
**
**	Applied patch by Gary Windham <windhamg@email.arizona.edu> to add
**	tcp wrappers support.
**
**	Revision 1.14  2003/05/20 19:04:23  dgm
**	Comment changes only.
**
**	Revision 1.13  2003/05/15 11:34:34  dgm
**	Patch by Ken Murchison <ken@oceana.com> to clean up build process:
**	Conditionally include sys/param.h instead of defining MAXPATHLEN.
**
**	Revision 1.12  2003/05/13 14:19:00  dgm
**	Changed all uses of AF_INET constant to PF_INET.
**
**	Revision 1.11  2003/05/13 11:40:16  dgm
**	Patches by Ken Murchison <ken@oceana.com> to clean up build process.
**
**	Revision 1.10  2003/05/06 12:12:21  dgm
**	Applied patches by Ken Murchison <ken@oceana.com> to include SSL
**	support.
**
**	Revision 1.9  2003/04/16 12:15:52  dgm
**	Added support for syslog configuration.
**	Removed a few ifdef LINUXs by always storing tcp service port as
**	network short.
**
**	Revision 1.8  2003/02/20 12:55:03  dgm
**	SetBannerAndCapability() now checks to see if the server supports
**	UNSELECT and sets a flag in the global proxy config struct.
**
**	Revision 1.7  2003/02/19 13:01:40  dgm
**	Changes to SetBannerAndCapability() to strip out unsupported AUTH=
**	mechanisms from the capability string.
**
**	Revision 1.6  2003/01/27 13:58:18  dgm
**	patch by Frode Nordahl <frode@powertech.no> to allow
**	compilation on Linux platforms.
**
**	Revision 1.5  2002/12/17 14:25:14  dgm
**	Added support for global configuration structure.
**	Modified supported command line arguments.
**	Minor bugfixes from Gary Mills incorporated.
**
**	Revision 1.4  2002/09/06 13:33:05  dgm
**	Added code to ignore SIGPIPE and SIGHUP.
**
**	Revision 1.3  2002/08/30 17:08:35  dgm
**	oops.  forgot to initialize the trace mutex...
**
**	Revision 1.2  2002/08/28 15:56:24  dgm
**	replaced all internal logging calls with standard syslog calls.
**	Changed call to setrlimit such that it's now done dynamically,
**	based on the max number of connections we want to allow.
**
**	Revision 1.1  2002/07/03 12:07:51  dgm
**	Initial revision
**
*/


static char *sourceRevision = "$Revision$";
static char *sourceVersion = "$Id$";
static char *sourceAuthor = "$Author$";

#define _REENTRANT

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <pwd.h>
#include <syslog.h>
#include <signal.h>
#include <openssl/rand.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#endif

#include "common.h"
#include "imapproxy.h"


/*
 * Global variables.  Many of these things are global just as an optimization.
 * For example, there's no reason to have to do a hostname lookup every
 * single time we want to connect to the IMAP server.  We do it once and 
 * store it globally.
 */
char Banner[BUFSIZE];                /* banner line returned from IMAP svr */
unsigned int BannerLen;
char Capability[BUFSIZE];            /* IMAP capability line from server */
unsigned int CapabilityLen;
ISD_Struct ISD;                      /* global IMAP server descriptor */
ICC_Struct *ICC_free;                /* ICC free listhead */
ICC_Struct *ICC_HashTable[ HASH_TABLE_SIZE ];
IMAPCounter_Struct *IMAPCount;       /* global IMAP counter struct */
pthread_mutex_t mp;                  /* "main" mutex used for ICC sync */
pthread_mutex_t trace;               /* mutex used for username tracing */
char TraceUser[MAXUSERNAMELEN];      /* username we want to trace */
int Tracefd;                         /* fd of our trace file (always open) */
ProxyConfig_Struct PC_Struct;        /* Global configuration data */

#if HAVE_LIBSSL
SSL_CTX *tls_ctx;
static int verify_depth = 5;
static int verify_error = X509_V_OK;

static int verify_callback( int, X509_STORE_CTX *);
static int set_cert_stuff( SSL_CTX *, const char *, const char * );
#endif

#ifdef HAVE_LIBWRAP
int allow_severity = LOG_DEBUG;
int deny_severity = LOG_ERR;
char *service;
#endif

/*
 * Internal Prototypes
 */
static void SetBannerAndCapability( void );
static int ParseBannerAndCapability( char *, unsigned int,
				      char *, unsigned int, unsigned int );
static void ServerInit( void );
static int TestServerAlive( struct addrinfo *ai );
static void Daemonize( const char* );
static void Usage( void );



int main( int argc, char *argv[] )
{
    const char *fn = "main()";
    char f_randfile[ PATH_MAX ];
    int listensd;                      /* socket descriptor we'll bind to */
    int clientsd;                      /* incoming socket descriptor */
    int sockaddrlen;                       
    struct sockaddr_storage srvaddr;
    struct sockaddr_storage cliaddr;
    pthread_t ThreadId;                /* thread id of each incoming conn */
    pthread_t RecycleThread;           /* used just for the recycle thread */
    pthread_attr_t attr;               /* generic thread attribute struct */
    int rc, i, fd;
    unsigned int ui;
    struct linger lingerstruct;        /* for the socket reuse stuff */
    int flag;                          /* for the socket reuse stuff */
    ICC_Struct *ICC_tptr;             
    extern char *optarg;
    extern int optind;
    char ConfigFile[ MAXPATHLEN ];     /* path to our config file */
    char PidFile[ MAXPATHLEN ];		/* path to our pidfile */
#ifdef HAVE_LIBWRAP
    struct request_info r;             /* request struct for libwrap */
#endif
#if HAVE_LIBSSL
    int tls_options;
#endif
    struct addrinfo aihints, *ai;
    int gaierrnum;

    flag = 1;
    ConfigFile[0] = '\0';
    strncpy( PidFile, DEFAULT_PID_FILE, sizeof PidFile -1 );

    /*
     * Ignore signals we don't want to die from but we don't care enough
     * about to catch.
     */
    signal( SIGPIPE, SIG_IGN );
    signal( SIGHUP, SIG_IGN );
    

    while (( i = getopt( argc, argv, "f:p:h" ) ) != EOF )
    {
	switch( i )
	{
	case 'f':
	    /* user specified a config filename */
	    strncpy( ConfigFile, optarg, sizeof ConfigFile -1 );
	    ConfigFile[ sizeof ConfigFile - 1 ] = '\0';
	    syslog( LOG_INFO, "%s: Using configuration file '%s'",
		    fn, ConfigFile );
	    break;
        
        case 'p':
            /* user specified a pidfile */
            strncpy( PidFile, optarg, sizeof PidFile -1 );
            PidFile[ sizeof PidFile - 1 ] = '\0';
            syslog( LOG_INFO, "%s: Using pidfile '%s'",
            fn, PidFile );
            break;
        
	case 'h':
	    Usage();
	    exit( 0 );

	case '?':
	    Usage();
	    exit( 1 );
	}
    }


    /* 
     * Make sure we know which config file to use and then set our config
     * options.
     */
    if ( ! ConfigFile[0] )
    {
	strncpy( ConfigFile, DEFAULT_CONFIG_FILE, sizeof ConfigFile -1 );
	ConfigFile[ sizeof ConfigFile - 1 ] = '\0';
	syslog( LOG_INFO, "%s: Using default configuration file '%s'.",
		fn, ConfigFile );
    }

    SetDefaultConfigValues(&PC_Struct);
    SetConfigOptions( ConfigFile );
    SetLogOptions();

    /*
     * Just for logging purposes, are we doing SELECT caching or not?
     */
    if ( PC_Struct.enable_select_cache )
	syslog( LOG_INFO, "%s: SELECT caching is enabled", fn );
    else
	syslog( LOG_INFO, "%s: SELECT caching is disabled", fn );
	
    /*
     * Just for logging purposes, are the admin commands enabled or not?
     */
     if ( PC_Struct.enable_admin_commands )
	 syslog( LOG_INFO, "%s: Internal admin commands are enabled", fn );
     else
	 syslog( LOG_INFO, "%s: Internal admin commands are disabled", fn );
     

#ifdef HAVE_LIBWRAP
    /*
     * Set our tcpd service name
     */
    if (service = strrchr(argv[0], '/'))
	    service++;
    else
	    service = argv[0];
#endif

    /*
     * Initialize some stuff.
     */
    rc = pthread_mutex_init(&mp, NULL);
    if ( rc )
    {
	syslog(LOG_ERR, "%s: pthread_mutex_init() returned error [%d] initializing main mutex.  Exiting.", fn, rc );
	exit( 1 );
    }

    rc = pthread_mutex_init(&trace, NULL);
    if ( rc )
    {
	syslog(LOG_ERR, "%s: pthread_mutex_init() returned error [%d] initializing trace mutex.  Exiting.", fn, rc );
	exit( 1 );
    }

    TraceUser[0] = '\0';
    
    syslog( LOG_INFO, "%s: Allocating %d IMAP connection structures.", 
	    fn, PC_Struct.cache_size );

    ICC_free = (ICC_Struct *)malloc( ( sizeof ( ICC_Struct ) ) 
		       * PC_Struct.cache_size );
    
    if ( ! ICC_free )
    {
	syslog(LOG_ERR, "%s: malloc() failed to allocate [%d] IMAPConnectionContext structures: %s", fn, PC_Struct.cache_size, strerror( errno ) );
	exit( 1 );
    }
    
    memset( ICC_free, 0, sizeof ( ICC_Struct ) * PC_Struct.cache_size );
    
    ICC_tptr = ICC_free;

    /*
     * Bug fixed by Gary Mills <mills@cc.UManitoba.CA>.  I was pre-incrementing
     * ICC_tptr and then assigning.  I guess gcc evaluates the expression
     * incorrectly, since I never had a problem with this.  Gary had the
     * problem with cc, so it's fixed here.
     */
    for ( ui = 0; ui < PC_Struct.cache_size - 1; ui++ )
    {
	ICC_tptr->next = ICC_tptr + 1;
	ICC_tptr++;
    }
    
    memset( ICC_HashTable, 0, sizeof ICC_HashTable );


#if HAVE_LIBSSL
    /* Initialize SSL_CTX */
    syslog( LOG_INFO, "%s: Enabling openssl library.", fn );
    SSL_library_init();

    /* Set up OpenSSL thread protection */
    ssl_thread_setup(fn);

    /* Need to seed PRNG, too! */
    if ( RAND_egd( ( RAND_file_name( f_randfile, sizeof( f_randfile ) ) == f_randfile ) ? f_randfile : "/.rnd" ) )
    {
	/* Not an EGD, so read and write it. */
	if ( RAND_load_file( f_randfile, -1 ) )
	RAND_write_file( f_randfile );
    }

    SSL_load_error_strings();

    /* 
     * Despite its name, SSLv23_client_method() negociates highest
     * version possible, which includes TLSv1.0, TLSv1.1, and TLSv1.2. 
     * SSLv2 and SSLv3 are disabled using SSL_OP_NO_SSLv2 and 
     * SSL_OP_NO_SSLv3 below.
     */ 
    tls_ctx = SSL_CTX_new( SSLv23_client_method() );
    if ( tls_ctx == NULL )
    { 
	syslog(LOG_ERR, "%s: Failed to create new SSL_CTX.  Exiting.", fn);
	exit( 1 );
    }
 
    /* Work around all known bugs, disable SSLv2 and SSLv3 */
    tls_options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

    if ( PC_Struct.tls_no_tlsv1 ) 
        tls_options |= SSL_OP_NO_TLSv1;

    if ( PC_Struct.tls_no_tlsv1_1 ) 
        tls_options |= SSL_OP_NO_TLSv1_1;

    if ( PC_Struct.tls_no_tlsv1_2 ) 
        tls_options |= SSL_OP_NO_TLSv1_2;

    SSL_CTX_set_options( tls_ctx, tls_options );
 
    if ( PC_Struct.tls_ca_file != NULL || PC_Struct.tls_ca_path != NULL )
    {
	rc = SSL_CTX_load_verify_locations( tls_ctx,
					    PC_Struct.tls_ca_file,
					    PC_Struct.tls_ca_path );
    }
    else
    {
	rc = SSL_CTX_set_default_verify_paths( tls_ctx );
    }
    if ( rc == 0 )
    { 
	syslog(LOG_ERR, "%s: Failed to load CA data.  Exiting.", fn);
	exit( 1 );
    }
 
    if ( ! set_cert_stuff( tls_ctx,
			    PC_Struct.tls_cert_file,
			    PC_Struct.tls_key_file ) )
    { 
	syslog(LOG_ERR, "%s: Failed to load cert/key data.  Exiting.", fn);
	exit( 1 );
    }

    if ( PC_Struct.tls_verify_server ) 
        SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, verify_callback);
    else
        SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, verify_callback);

    if ( PC_Struct.tls_ciphers != NULL )
    {
        SSL_CTX_set_cipher_list( tls_ctx, PC_Struct.tls_ciphers );    
    }

    /* Enable ECDHE is OpenSSL has it */
#ifdef NID_X9_62_prime256v1
    {
        EC_KEY *ecdh;

        ecdh = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
        SSL_CTX_set_tmp_ecdh( tls_ctx, ecdh );
        EC_KEY_free( ecdh );
    }
#endif
#endif /* HAVE_LIBSSL */


    ServerInit();
    
    /* Daemonize() would go here */

    SetBannerAndCapability();
    

    /*
     * We don't need to check PC_Struct.support_starttls since we
     * probably have refetched the capability list after a STARTTLS
     * if we did one; it won't ever be supported at this point.
     *
     * It also makes no difference to check PC_Struct.force_tls now
     * because we've either done a STARTTLS or we haven't - all that
     * matters is if we got LOGINDISABLED or not.
     *
     * Note that all these things *ARE* tested when checking the
     * server capabilities (in fact, the following check is probably
     * a duplicate).
     */
    if ( PC_Struct.login_disabled )
    {
	/* We're screwed!  We can't login */
	syslog(LOG_ERR,
		"%s: IMAP server has LOGINDISABLED.  Exiting.",
		fn);
	exit( 1 );
    }


    memset( &aihints, 0, sizeof aihints );
    aihints.ai_family = AF_UNSPEC;
    aihints.ai_socktype = SOCK_STREAM;
    aihints.ai_flags = AI_PASSIVE;

    if ( ( gaierrnum = getaddrinfo( PC_Struct.listen_addr,
				    PC_Struct.listen_port,
				    &aihints, &ai ) ) )
	{
	    syslog( LOG_ERR, "%s: bad bind address: '%s' specified in config file.  Exiting.", fn, PC_Struct.listen_addr );
	    exit( 1 );
	}

    syslog( LOG_INFO, "%s: Binding to tcp %s:%s", fn,
	    PC_Struct.listen_addr ? PC_Struct.listen_addr : "*",
	    PC_Struct.listen_port );

    for ( ; ai != NULL; ai = ai->ai_next )
    {
	listensd = socket( ai->ai_family, ai->ai_socktype, ai->ai_protocol );
    if ( listensd == -1 )
    {
	    syslog(LOG_WARNING, "%s: socket() failed: %s", fn, strerror(errno));
	    continue;
    }

    setsockopt(listensd, SOL_SOCKET, SO_REUSEADDR, (void *)&flag, 
	       sizeof(flag));
    lingerstruct.l_onoff = 1;
    lingerstruct.l_linger = 5;
    setsockopt(listensd, SOL_SOCKET, SO_LINGER, (void *)&lingerstruct, 
	       sizeof(lingerstruct));

    if ( PC_Struct.send_tcp_keepalives )
    {
	lingerstruct.l_onoff = 1;
	syslog( LOG_INFO, "%s: Enabling SO_KEEPALIVE.", fn );
	setsockopt( listensd, SOL_SOCKET, SO_KEEPALIVE, (void *)&lingerstruct.l_onoff, sizeof lingerstruct.l_onoff );
    }

	memcpy( &srvaddr, ai->ai_addr, ai->ai_addrlen );
	if ( bind( listensd, (struct sockaddr *)&srvaddr, ai->ai_addrlen ) < 0 )
    {
	    syslog(LOG_WARNING, "%s: bind() failed: %s", fn, strerror(errno) );
	    continue;
	}
	else break;
    }
    if ( ai == NULL )
    {
	syslog( LOG_ERR, "%s: no useable addresses to bind to", fn );
	exit( EXIT_FAILURE);
    }

    /*
     * Create and mmap() our stat file while we're still root.  Since it's
     * configurable, we want to make sure we do this as root so there's the
     * greatest possibility that we'll have permission to write where we
     * need to.
     */
    syslog( LOG_INFO, "%s: Using global statistics file '%s'", fn,
	    PC_Struct.stat_filename );
    
    fd = open( PC_Struct.stat_filename, O_RDWR | O_CREAT, S_IREAD | S_IWRITE );
    if ( fd == -1 )
    {
	syslog(LOG_ERR, "%s: open() failed for '%s': %s -- Exiting.", fn, 
	       PC_Struct.stat_filename, strerror( errno ) );
	exit( 1 );
    }
    
    if ( ( ftruncate( fd, sizeof( IMAPCounter_Struct ) ) ) == -1 )
    {
	syslog(LOG_ERR, "%s: ftruncate() failed: %s -- Exiting.", 
	       fn, strerror( errno ) );
	exit( 1 );
    }
    
    IMAPCount = ( IMAPCounter_Struct *)mmap( 0, sizeof( IMAPCounter_Struct ), 
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
    
    if ( IMAPCount == MAP_FAILED )
    {
	syslog(LOG_ERR, "%s: mmap() failed: %s -- Exiting.", 
	       fn, strerror( errno ) );
	exit( 1 );
    }
    
    memset( IMAPCount, 0, sizeof( IMAPCounter_Struct ) );
    IMAPCount->StartTime = time( 0 );
    IMAPCount->CountTime = time( 0 );

    /*
     * Daemonize as late as possible, so that connection failures can be caught
     * and startup aborted before dettaching from parent
     */
    Daemonize( PidFile );

    if ( BecomeNonRoot() )
	exit( 1 );

    /* some misc thread setup */
    rc = pthread_attr_init( &attr );
    if ( rc )
    {
	syslog(LOG_ERR, "%s: pthread_attr_init() failed: [%d]\n", fn, rc);
	exit( 1 );
    }
    
    rc = pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );
    if ( rc )
    {
	syslog(LOG_ERR, "%s: pthread_attr_setdetachstate() failed: [%d]\n", 
	       fn, rc);
	exit( 1 );
    }

    /* launch a recycle thread before we loop */
    pthread_create( &RecycleThread, &attr, (void *)ICC_Recycle_Loop, NULL );

    syslog(LOG_INFO, "%s: Launched ICC recycle thread with id %d", 
	   fn, (int)RecycleThread );

    /*
     * Now start listening and accepting connections.
     */
    if ( listen(listensd, MAX_CONN_BACKLOG) < 0)
    {
	syslog( LOG_ERR, "%s: listen() failed: %s -- Exiting", 
	       fn, strerror(errno));
	exit( 1 );
    }

    syslog( LOG_INFO, "%s: squirrelmail-imap_proxy version %s normal server startup.", fn, IMAP_PROXY_VERSION );

    /*
     * Main server loop
     */
    for ( ;; )
    {
	/*
	 * Bug fixed by Gary Mills <mills@cc.UManitoba.CA>.  I forgot
	 * to initialize sockaddrlen.
	 */
	sockaddrlen = sizeof cliaddr;
	clientsd = accept( listensd, (struct sockaddr *)&cliaddr,
			   &sockaddrlen );
	if ( clientsd == -1 )
	{
	    syslog(LOG_WARNING, "%s: accept() failed: %s -- retrying", 
		   fn, strerror(errno));
	    sleep( 1 );
	    continue;
	}

#ifdef HAVE_LIBWRAP
	request_init(&r, RQ_DAEMON, service, 0);
	request_set(&r, RQ_FILE, clientsd, 0);
	sock_host(&r);
	if (!hosts_access(&r))
	{
	    shutdown(clientsd, SHUT_RDWR);
	    close(clientsd);
	    syslog(deny_severity, "refused connection from %s", eval_client(&r));
	    continue;
	}
#endif

	IMAPCount->TotalClientConnectionsAccepted++;
	IMAPCount->CurrentClientConnections++;
	
	if ( IMAPCount->CurrentClientConnections > 
	     IMAPCount->PeakClientConnections )
	    IMAPCount->PeakClientConnections = IMAPCount->CurrentClientConnections;
	
	rc = pthread_create( &ThreadId, &attr, (void *)HandleRequest, (void *)clientsd );
	if (rc != 0) {
	    syslog(LOG_ERR, "%s: pthread_create() returned error [%d] for HandleRequest.", fn, rc );
	    close(clientsd);
	}
	
    }
}

	
    
    
	
/*
 * Function definitions.
 */



/*++
 * Function:	Usage
 *
 * Purpose:	Display a usage string to stdout
 *
 * Parameters:	None.
 *
 * Returns:	nada
 * 
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 * 
 * Notes:
 *--
 */
void Usage( void )
{
    printf("Usage: %s [-f config filename] [-p pidfile] [-h]\n", PGM );
    return;
}



/*++
 * Function:	ServerInit
 *
 * Purpose:	Initialize some stuff.  Set some global variables.
 *
 * Parameters:	none
 *
 * Returns:	nada -- exits on error
 * 
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 * 
 * Notes:       relies on global copy of ProxyConfig_Struct "PC_Struct"
 *--
 */
static void ServerInit( void ) 
{
    char *fn = "ServerInit()";
    struct rlimit rl;
    int rc, retry;
    struct passwd *pw;
    struct addrinfo aihints, *ai;
    int gaierrnum;

    
    /* open the global trace file and make proc_username own it */
    syslog( LOG_INFO, "%s: Using '%s' for global protocol logging file.",
	    fn, PC_Struct.protocol_log_filename );
    
    Tracefd = open( PC_Struct.protocol_log_filename,
		    O_RDWR | O_CREAT | O_TRUNC, 0600 );
    
    if ( Tracefd == -1 )
    {
	syslog(LOG_ERR, "%s: open() failed for '%s': %s -- Exiting.", fn,
	       PC_Struct.protocol_log_filename, strerror( errno ) );
	exit( 1 );
    }

    if ( ( pw = getpwnam( PC_Struct.proc_username ) ) == NULL )
    {
	syslog(LOG_ERR, "%s: getpwnam() failed for user '%s' -- Exiting.", fn, 
	       PC_Struct.proc_username );
	exit( 1 );
    }
    
    rc = chown( PC_Struct.protocol_log_filename, pw->pw_uid, pw->pw_gid );
    
    if ( rc )
    {
	syslog(LOG_ERR, "%s: Failed to set ownership of file '%s' to '%s': %s -- Exiting.", fn, PC_Struct.protocol_log_filename, PC_Struct.proc_username, strerror( errno ) );
	exit( 1 );
    }
    
    /* 
     * increase the number of open file descriptors we're allowed.  Base
     * This number on the number of simultaneous connections we allow.
     * Also allow stdin, stdout, stderr and a few misc pipes and doors.
     */
    rl.rlim_cur = ( PC_Struct.cache_size * 2 ) + 10;
    rl.rlim_max = ( PC_Struct.cache_size * 2 ) + 10;

    rc = setrlimit( RLIMIT_NOFILE, &rl );

    if ( rc )
    {
	syslog(LOG_ERR, "%s: setrlimit() failed to set max number of open file descriptors to %d: %s", fn, ( PC_Struct.cache_size * 2 + 10), strerror( errno ) );
	exit(1);
    }
    
    
    /* grab a host entry for the IMAP server. */
    syslog( LOG_INFO, "%s: proxying to IMAP server '%s'.", fn, 
	    PC_Struct.server_hostname );
    
    memset( &aihints, 0, sizeof aihints );
    aihints.ai_family = AF_UNSPEC;
    aihints.ai_socktype = SOCK_STREAM;

    for( ;; )
    {
	if ( ( gaierrnum = getaddrinfo( PC_Struct.server_hostname,
					PC_Struct.server_port,
					&aihints, &ai ) ) )
	{
	    syslog( LOG_ERR,
		    "%s: getaddrinfo() failed to resolve hostname of remote IMAP server: %s -- retrying",
		    fn, gai_strerror( gaierrnum ) );
	    sleep( 15 );
	}
	else
	{
	    break;
	}
    }

    syslog(LOG_INFO, "%s: Proxying to IMAP port %s", 
           fn, PC_Struct.server_port );
        
    // Since IMAP Proxy uses STARTTLS and does not speak "imaps",
    // let's spit out an informative warning message if the server
    // port was configured to 993, which, 99.9% of the time, is a
    // mistake
    //
    if (strcmp(PC_Struct.server_port, "993") == 0)
        syslog(LOG_ERR, "WARNING: IMAP Proxy uses STARTTLS to encrypt a \"normal\" IMAP connection and does not support direct TLS/SSL connections that are typically served on port 993 (but there is a way around this if the server is only available on that port - see README.ssl).  Chances are you have misconfigured the server_port setting, and that it should be something more like port 143.  If the server at '%s' supports STARTTLS from an unencrypted connection on port 993, then you can ignore this (but, again, chances are that this is NOT the case).", PC_Struct.server_hostname);

    /* 
     * fill in the address family, the host address, and the
     * service port of our global socket address structure
     * Try to connect at least once (<=) before giving up
     */
    ISD.airesults = ai;
    ISD.srv = NULL;
    for ( retry=0; retry <= PC_Struct.server_connect_retries && NULL == ISD.srv; retry++ )
    {
        ai = ISD.airesults;
        for ( ; ai != NULL; ai = ai->ai_next )
        {
            if( ! TestServerAlive(ai) )
            {	/* connect to server succeeded */
                ISD.srv = ai;
                break;
            }
	}
	if( ISD.srv )
	    break;
        
	syslog( LOG_INFO, "%s: Connection to server failed. Sleeping %d seconds to retry...", fn,
	    PC_Struct.server_connect_delay);
	sleep( PC_Struct.server_connect_delay );
    }
    if ( ai == NULL )
    {
	syslog( LOG_ERR, "%s: %s -- exiting", fn, strerror( errno ) );
	exit( EXIT_FAILURE );
    }
}

/*++
 * Function:   TestServerAlive
 *
 * Purpose:    Attempt connecting to server
 *
 * Parameters: ai -- addrinfo corresponding to resolved server address
 *
 * Returns:    0 upon successful connection
 *
 * Authors:    Jose Luis Tallon <jltallon@adv-solutions.net>
 *
 */
int TestServerAlive(struct addrinfo *ai)
{
 int sd=-1;
 
     if( ( sd=socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol) ) < 0 )
         return -1;	/* could not create socket */

     if( connect(sd, (struct sockaddr *)ai->ai_addr, ai->ai_addrlen) )
         return -1;	/* could not connect socket */

     close( sd );
     return 0;
}

/*++
 * Function:   Daemonize
 *
 * Purpose:    Daemonize, closing all unneeded descriptors.
 *             Write the daemon's PID into 'pidfile'
 *
 * Parameters: pidfile -- where to write our PID.
 *
 * Returns:    nada -- exits on error
 *
 * Authors:    Jose Luis Tallon <jltallon@adv-solutions.net>
 *
 * Notes:
 *--
 */
void Daemonize( const char* pidfile )
{
 const char* fn="Daemonize()";
 FILE* fp=NULL;
 pid_t pid;                         /* used just for a fork call */
 int i;

    /* detach from our parent if necessary */
    if (! (getppid() == 1) && ( ! PC_Struct.foreground_mode ) )
    {
	syslog( LOG_INFO, "%s: Configured to run in background mode.", fn );

	if ( (pid = fork()) < 0)
	{
		syslog(LOG_ERR, "%s: initial call to fork() failed: %s",
			fn, strerror(errno));
		exit( 1 );
	}
	else if ( pid > 0)
	{
		exit( 0 );
	}

	if (setsid() == -1)
	{
		syslog(LOG_WARNING, "%s: setsid() failed: %s",
			fn, strerror(errno));
	}
	if ( (pid = fork()) < 0)
	{
		syslog(LOG_ERR, "%s: secondary call to fork() failed: %s",
			fn, strerror(errno));
		exit( 1 );
	}
	else if ( pid > 0)
	{
		exit( 0 );
	}
	if ( (fp=fopen(pidfile,"wt")) == NULL )
	{
		syslog(LOG_ERR, "%s: creating pidfile '%s' failed: %s", fn,
			pidfile, strerror(errno));
		exit(1);
	}
	if( fprintf(fp, "%u\n", (unsigned)getpid()) < 0 )
	{
		syslog(LOG_ERR, "%s: fprintf on pidfile failed: %s", fn,
			strerror(errno));
		exit(1);
	}
	fclose(fp);
	if( chdir("/") < 0 )
	{
		syslog(LOG_ERR, "%s: chdir(\"/\") failed: %s", fn,
			strerror(errno));
		exit( 1 );
	}
	if( (i=open("/dev/null",O_RDWR)) < 0 )
	{
		syslog(LOG_ERR, "%s: open(\"/dev/null\") failed: %s", fn,
		strerror(errno));
		exit( 1 );
	}
	close(2); dup(i);
	close(1); dup(i);
	close(0); dup(i);
	close(i);
    }
    else
    {
	syslog( LOG_INFO, "%s: Configured to run in foreground mode.", fn );
    }
}

/*++
 * Function:	ParseBannerAndCapability
 *
 * Purpose:	Weed out stuff that squirrelmail-imap_proxy does not
 *              support from a banner line or a capability line.
 *
 * Parameters:	char * - Buffer for storing the cleaned up string.
 *              unsigned int - buflen
 *              char * - ptr to the string that needs to be cleaned up.
 *              unsigned int - buflen
 *
 * Returns:	Number of bytes in the output string.
 *              exit()s on failure.
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:       The buffer that the third argument points to will be tokenized
 *              so make a copy of it first if you care about that.
 *--
 */
static int ParseBannerAndCapability( char *DestBuf,
				      unsigned int DestBufSize,
				      char *SourceBuf,
				      unsigned int SourceBufSize,
				      unsigned int capability )
{
    char *fn = "ParseBannerAndCapability";
    char *CP;
    char *bracket;
    unsigned int CPlen;
    unsigned int inCap = 0;
    unsigned int endbracket = 0;
    
    if ( SourceBufSize >= DestBufSize )
    {
	syslog( LOG_ERR, "%s: Unable to parse banner or capability because it would cause a buffer overflow -- exiting.", fn );
	exit( 1 );
    }
    
    syslog( LOG_INFO, "%s: Attempting to parse capability string: %s", fn, SourceBuf);
    
    /*
     * strip out all of the AUTH mechanisms except the ones that we support.
     * Right now, this is just AUTH=LOGIN.  Note that the use of
     * non-MT safe strtok is okay here.  This function is called before any
     * other threads are launched and should never be called again.
     */
    SourceBuf[SourceBufSize - 2] = '\0';
    CP = strtok( SourceBuf, " " );
    
    if ( !CP )
    {
	syslog( LOG_ERR, "%s: No tokens found in banner or capability from IMAP server -- exiting.", fn);
	exit( 1 );
    }
    
    sprintf( DestBuf, "%s", CP );
    
    /*
     * initially assume that the server doesn't support UNSELECT.
     */
    PC_Struct.support_unselect = UNSELECT_NOT_SUPPORTED;

    /*
     * initially assume that the server doesn't support STARTTLS.
     */
    PC_Struct.support_starttls = STARTTLS_NOT_SUPPORTED;

    /*
     * initially assume that the server doesn't disable LOGIN.
     */
    PC_Struct.login_disabled = LOGIN_NOT_DISABLED;

    for( ; ; )
    {
	if (endbracket)
	{
	    /*
	     * Add the XIMAPPROXY capability string at the end of the 
	     * CAPABILITY listing.
	     */
	    endbracket = 0;
 	    inCap = 0;
	    strcat( DestBuf, " XIMAPPROXY]" );

	    continue;
	}

	CP = strtok( NULL, " " );
	
	if ( !CP )
	    break;

	/*
	 * Don't parse CAPABILITY extensions until we know we are either in
	 * a CAPABILITY untagged response or a CAPABILTY status response. 
	 */
	if ( ( capability &&
	       !strncasecmp( CP, "CAPABILITY", strlen( "CAPABILITY" ) ) ) ||
	     ( !capability &&
	       !strncasecmp( CP, "[CAPABILITY", strlen( "[CAPABILITY" ) ) ) )
	{
	    /*
	     * Indicate that we are now in CAPABILITY data
	     */
	    inCap = 1;
	}
	else if ( inCap )
	{
	    /*
	     * If we are in a CAPABILITY status response, we keep processing
	     * until we see a ']' character.
	     */
	    if ( capability == 0 )
	    {	
		CPlen = strlen( CP );
		bracket = memchr( CP, ']', CPlen );

		if ( bracket )
		{
		    endbracket = 1;
		    CP[CPlen - 1] = '\0';
		}
	    }

	    if ( !strncasecmp( CP, "UNSELECT", strlen( "UNSELECT" ) ) )
	    {
	        PC_Struct.support_unselect = UNSELECT_SUPPORTED;
	    }
	
	    /*
	     * If this token happens to be an auth mechanism, we want to
	     * discard it unless it's an auth mechanism we can support.
	     */
	    if ( ! strncasecmp( CP, "AUTH=", strlen( "AUTH=" ) ) &&
	         ( strncasecmp( CP, "AUTH=LOGIN", strlen( "AUTH=LOGIN" ) ) ) )
	    {
	        continue;
	    }

	    /*
	     * If this token happens to be SASL-IR, we want to discard it
	     * since we don't support any auth mechs that can use it.
	     */
	    if ( ! strncasecmp( CP, "SASL-IR", strlen( "SASL-IR" ) ) )
	    {
	        continue;
	    }

	    /*
	     * If this token is IDLE, discard it.
	     *
	     */
	    if ( ! strncasecmp( CP, "IDLE", strlen( "IDLE" ) ) )
	    {
	        continue;
	    }

	    /*
	     * If this token happens to be STARTTLS, we want to discard it
	     * since we don't support it on the client-side.
	     */
	    if ( ! strncasecmp( CP, "STARTTLS", strlen( "STARTTLS" ) ) )
	    {
	        PC_Struct.support_starttls = STARTTLS_SUPPORTED;
	        //syslog( LOG_INFO, "%s: Found out the server supports STARTTLS, even though we don't", fn);
	        continue;
	    }
	
	    /*
	     * If this token happens to be LOGINDISABLED, we want to discard it
	     * since we don't support it on the client-side.
	     */
	    if ( ! strncasecmp( CP, "LOGINDISABLED", strlen( "LOGINDISABLED" ) ) )
	    {
	        PC_Struct.login_disabled = LOGIN_DISABLED;
	        continue;
	    }
	}
	
	strcat( DestBuf, " ");
	strcat( DestBuf, CP );
    }
    
    /*
     * Add a 'XIMAPPROXY' CAPABILITY response to indicate that the
     * current connection is handled by squirrelmail-imap_proxy.
     */
    if ( capability == 1 )
    {
	strcat( DestBuf, " XIMAPPROXY" );
    }

    strcat( DestBuf, "\r\n" );

    return( strlen( DestBuf ) );
}


/*++
 * Function:	SetBannerAndCapability
 *
 * Purpose:	Connect to an IMAP server as a client and fetch the initial
 *		banner string and the output from a CAPABILITY command.
 *
 * Parameters:	none
 *
 * Returns:	nuttin -- exits if there's a problem
 *
 * Authors:	Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:       All AUTH mechanisms will be stripped from the capability
 *              string.  AUTH=LOGIN will be added.
 *              The support_unselect flag in the global copy of the
 *              ProxyConfig struct will be set in this function depending on
 *              whether the server supports UNSELECT or not.
 *--
 */
static void SetBannerAndCapability( void )
{
    int sd;
    ITD_Struct itd;
    ICD_Struct conn;
    int BytesRead;
    char *fn = "SetBannerAndCapability()";

    /* initialize some stuff */
    memset( &itd, 0, sizeof itd );

    for ( ;; )
    {
	sd = socket( ISD.srv->ai_family, ISD.srv->ai_socktype,
		     ISD.srv->ai_protocol );
	if ( sd == -1 )
	{
	    syslog(LOG_ERR, "%s: socket() failed: %s -- exiting", fn, 
		   strerror(errno) );
	    exit( 1 );
	}
	
	if ( connect( sd, (struct sockaddr *)ISD.srv->ai_addr, 
		      ISD.srv->ai_addrlen ) == -1 ) 	{
	    syslog(LOG_ERR, "%s: connect() to IMAP server on socket [%d] failed: %s -- retrying", fn, sd, strerror(errno));
	    close( sd );
	    
	    sleep( 15 );    /* IMAP server may not be started yet. */
	}
	else
	{
	    break;  /* Success */
	}
    }
    
    
    memset( &conn, 0, sizeof ( ICD_Struct ) );
    itd.conn = &conn;
    itd.conn->sd = sd;
    
    /*
     * The first thing we get back from the server should be the
     * banner string.
     */
    BytesRead = IMAP_Line_Read( &itd );
    if ( BytesRead == -1 )
    {
	syslog( LOG_ERR, "%s: Error reading banner line from server on initial connection: %s -- Exiting.", fn, strerror( errno ) );
	close( itd.conn->sd );
	exit( 1 );
    }

    if ( itd.LiteralBytesRemaining )
    {
	syslog( LOG_ERR, "%s: Server sent unexpected literal specifier in banner response -- Exiting.", fn );
	exit( 1 );
    }
    

    BannerLen = ParseBannerAndCapability( Banner, sizeof Banner - 1,
					  itd.ReadBuf, BytesRead, 0 );
    
    /*
     * See if the string we got back starts with "* OK" by comparing the
     * first 4 characters of the buffer.
     */
    if ( strncasecmp( Banner, IMAP_UNTAGGED_OK, strlen(IMAP_UNTAGGED_OK)) )
    {
	syslog(LOG_ERR, "%s: Unexpected response from IMAP server on initial connection: %s -- Exiting.", fn, Banner);
	close( itd.conn->sd );
	exit( 1 );
    }


    /* Now we send a CAPABILITY command to the server. */
    if ( IMAP_Write( itd.conn, "1 CAPABILITY\r\n", strlen("1 CAPABILITY\r\n") ) == -1 )
    {
	syslog(LOG_ERR, "%s: Unable to send capability command to server: %s -- exiting.", fn, strerror(errno) );
	close( itd.conn->sd );
	exit( 1 );
    }
    
    /*
     * From RFC2060:
     * The server MUST send a single untagged
     * CAPABILITY response with "IMAP4rev1" as one of the listed
     * capabilities before the (tagged) OK response.
     *
     * The means we should read exactly 2 lines of data back from the server.
     * The first will be the untagged capability line.
     * The second will be the OK response with the tag in it.
     */

    BytesRead = IMAP_Line_Read( &itd );
    if ( BytesRead == -1 )
    {
	syslog( LOG_ERR, "%s: Failed to read capability response from server: %s --  exiting.", fn, strerror( errno ) );
	close( itd.conn->sd );
	exit( 1 );
    }

    if ( itd.LiteralBytesRemaining )
    {
	syslog( LOG_ERR, "%s: Server sent unexpected literal specifier in CAPABILITY response -- Exiting.", fn );
	close( itd.conn->sd );
	exit ( 1 );
	
    }
    
    CapabilityLen = ParseBannerAndCapability( Capability, sizeof Capability - 1,
					      itd.ReadBuf, BytesRead, 1 );
    
    /* Now read the tagged response and make sure it's OK */
    BytesRead = IMAP_Line_Read( &itd );
    if ( BytesRead == -1 )
    {
	syslog( LOG_ERR, "%s: Failed to read capability response from server: %s -- exiting.", fn, strerror( errno ) );
	close( itd.conn->sd );
	exit( 1 );
    }

    if ( itd.LiteralBytesRemaining )
    {
	syslog( LOG_ERR, "%s: Server sent unexpected literal specifier in tagged CAPABILITY response -- exiting.", fn );
	exit( 1 );
    }
    
    if ( strncasecmp( itd.ReadBuf, IMAP_TAGGED_OK, strlen(IMAP_TAGGED_OK) ) )
    {
	syslog(LOG_ERR, "%s: Received non-OK tagged reponse from IMAP server on CAPABILITY command -- exiting.", fn );
	close( itd.conn->sd );
	exit( 1 );
    }
    
    /*
     * If we're using it, attempt STARTTLS before doing one more
     * CAPABILITY so our capability string is accurate
     */
    if ( PC_Struct.login_disabled || PC_Struct.force_tls )
    {
#if HAVE_LIBSSL
	if ( PC_Struct.support_starttls != STARTTLS_NOT_SUPPORTED )
	{
	    if ( Attempt_STARTTLS( &itd ) != 0 )
	    {
		syslog(LOG_ERR, "%s: STARTTLS failed for CAPABILITY check -- exiting.", fn );
		close( itd.conn->sd );
		exit( 1 );
	    }
	    else
	    {
		/*
		 * STARTTLS was successful, so we can proceed
		 * to get the new CAPABILITY list - first,
		 * send a CAPABILITY command to the server.
		 */
		if ( IMAP_Write( itd.conn, "1 CAPABILITY\r\n", strlen("1 CAPABILITY\r\n") ) == -1 )
		{
		    syslog(LOG_ERR, "%s: Unable to send capability command to server: %s -- exiting.", fn, strerror(errno) );
		    close( itd.conn->sd );
		    exit( 1 );
		}

		/*
		 * From RFC2060:
		 * The server MUST send a single untagged
		 * CAPABILITY response with "IMAP4rev1" as one of the listed
		 * capabilities before the (tagged) OK response.
		 *
		 * The means we should read exactly 2 lines of data back from the server.
		 * The first will be the untagged capability line.
		 * The second will be the OK response with the tag in it.
		 */

		BytesRead = IMAP_Line_Read( &itd );
		if ( BytesRead == -1 )
		{
		    syslog( LOG_ERR, "%s: Failed to read capability response from server: %s --  exiting.", fn, strerror( errno ) );
		    close( itd.conn->sd );
		    exit( 1 );
		}

		if ( itd.LiteralBytesRemaining )
		{
		    syslog( LOG_ERR, "%s: Server sent unexpected literal specifier in CAPABILITY response -- Exiting.", fn );
		    close( itd.conn->sd );
		    exit ( 1 );
		}

		CapabilityLen = ParseBannerAndCapability( Capability, sizeof Capability - 1,
		itd.ReadBuf, BytesRead, 1 );

		/* Now read the tagged response and make sure it's OK */
		BytesRead = IMAP_Line_Read( &itd );
		if ( BytesRead == -1 )
		{
		    syslog( LOG_ERR, "%s: Failed to read capability response from server: %s -- exiting.", fn, strerror( errno ) );
		    close( itd.conn->sd );
		    exit( 1 );
		}

		if ( itd.LiteralBytesRemaining )
		{
		    syslog( LOG_ERR, "%s: Server sent unexpected literal specifier in tagged CAPABILITY response -- exiting.", fn );
		    exit( 1 );
		}

		if ( strncasecmp( itd.ReadBuf, IMAP_TAGGED_OK, strlen(IMAP_TAGGED_OK) ) )
		{
		    syslog(LOG_ERR, "%s: Received non-OK tagged reponse from imap server on CAPABILITY command -- exiting.", fn );
		    close( itd.conn->sd );
		    exit( 1 );
		}
	    }
	}
	else
#endif /* HAVE_LIBSSL */
	{
	    /* We're screwed!  We won't be able to login without SASL */
	    syslog(LOG_ERR,
		"%s: IMAP server has LOGINDISABLED and we can't do STARTTLS.  Exiting.",
		fn);
	    close( itd.conn->sd );
	    exit( 1 );
	}
    }
    else
    {
	//syslog( LOG_ERR, "%s: Not trying STARTTLS and second CAPABILITY.", fn );
    }

    /* Be nice and logout */
    if ( IMAP_Write( itd.conn, "2 LOGOUT\r\n", strlen("2 LOGOUT\r\n") ) == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Write() failed on LOGOUT: %s -- Ignoring", fn, strerror(errno) );
	close( itd.conn->sd );
	return;
    }
    
    /* read the final OK logout */
    BytesRead = IMAP_Line_Read( &itd );
    if ( BytesRead == -1 )
    {
	syslog(LOG_WARNING, "%s: IMAP_Line_Read() failed on LOGOUT -- Ignoring", fn );
    }

    if ( itd.LiteralBytesRemaining )
    {
	syslog( LOG_WARNING, "%s: Server sent unexpected literal specifier in LOGOUT response -- Ignoring", fn );
    }
        
    close( itd.conn->sd );
    return;
}
    

#if HAVE_LIBSSL
/* taken from OpenSSL apps/s_cb.c */

static int verify_callback(int ok, X509_STORE_CTX * ctx)
{
    char    buf[256];
    X509   *err_cert;
    int     err;
    int     depth;

    syslog(LOG_DEBUG,"Doing a peer verify");

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));
    if (ok==0)
    {
      syslog(LOG_ERR, "verify error:num=%d:%s", err,
	     X509_verify_cert_error_string(err));
      
	if (verify_depth >= depth) {
	    ok = 0;
	    verify_error = X509_V_OK;
	} else {
	    ok = 0;
	    verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	}
    }
    switch (ctx->error) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, sizeof(buf));
	syslog(LOG_NOTICE, "issuer= %s", buf);
	break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	syslog(LOG_NOTICE, "cert not yet valid");
	break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	syslog(LOG_NOTICE, "cert has expired");
	break;
    }

    return (ok);
}


static int set_cert_stuff(SSL_CTX * ctx,
			  const char *cert_file, const char *key_file)
{
    if (cert_file != NULL) {
	if (SSL_CTX_use_certificate_file(ctx, cert_file,
					 SSL_FILETYPE_PEM) <= 0) {
	    syslog(LOG_ERR, "unable to get certificate from '%s'", cert_file);
	    return (0);
	}
	if (key_file == NULL)
	    key_file = cert_file;
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file,
					SSL_FILETYPE_PEM) <= 0) {
	    syslog(LOG_ERR, "unable to get private key from '%s'", key_file);
	    return (0);
	}
	/* Now we know that a key and cert have been set against
         * the SSL context */
	if (!SSL_CTX_check_private_key(ctx)) {
	    syslog(LOG_ERR,
		   "Private key does not match the certificate public key");
	    return (0);
	}
    }
    return (1);
}
#endif /* HAVE_LIBSSL */


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






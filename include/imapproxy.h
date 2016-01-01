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
**	imapproxy.h
**
**  Abstract:
**
**	Common definitions and function prototypes for the IMAP proxy server.
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
**      Revision 1.30  2009/10/16 14:35:17  dave64
**      Applied patch by Jose Luis Tallon to improve server connect retry logic.
**
**      Revision 1.29  2009/10/16 14:29:21  dave64
**      Applied patch by Jose Luis Tallon to allow for default config options.
**
**      Revision 1.28  2008/10/20 13:22:19  dave64
**      Applied patch by Michael M. Slusarz to support XPROXYREUSE.
**
**      Revision 1.27  2007/11/15 11:11:46  dave64
**      Added pidfile support patch by Jose Luis Tallón.
**
**      Revision 1.26  2007/05/31 12:07:41  dave64
**      Applied ipv6 patch by Antonio Querubin.
**
**      Revision 1.25  2007/05/31 11:46:00  dave64
**      Applied OpenSSL threads patch by Jan Grant.
**
**      Revision 1.24  2005/07/06 11:51:25  dgm
**      Added enable_admin_commands to struct ProxyConfig
**
**      Revision 1.23  2005/06/15 12:13:40  dgm
**      Changed all long int values to int.  Changed logouttime in
**      IMAPConnectionContext to time_t.  Added atoui function
**      prototype.  Patch by Dave Steinberg and Jarno Huuskonen to
**      allow chroot.
**
**      Revision 1.22  2005/01/12 17:51:19  dgm
**      Applied patch by David Lancaster to provide force_tls
**      config option.
**
**      Revision 1.21  2005/01/12 16:50:59  dgm
**      cache_size and cache_expiration_time in struct ProxyConfig now
**      declared as unsigned int instead of unsigned long.
**
**      Revision 1.20  2004/11/10 15:35:13  dgm
**      Changed LiteralBytesRemaining from signed long to unsigned long.
**
**      Revision 1.19  2004/10/11 18:00:42  dgm
**      Added foreground_mode configuration option.
**
**      Revision 1.18  2004/03/11 15:17:58  dgm
**      SELECT_BUF_SIZE size changed from 1024 to BUFSIZE which is
**      currently 4096
**
**      Revision 1.17  2004/02/24 15:21:01  dgm
**      Added support for SELECT caching.
**
**      Revision 1.16  2003/11/14 15:06:14  dgm
**      Patch by Geoffrey Hort <g.hort@unsw.edu.au> to include listen_address
**      config option.  Also, I changed the default buffer size from
**      1024 to 4096.
**
**      Revision 1.15  2003/10/09 15:05:01  dgm
**      Added tcp keepalive support.
**
**      Revision 1.14  2003/07/14 16:41:18  dgm
**      Applied patch by William Yodlowsky <wyodlows@andromeda.rutgers.edu> to
**      allow TLS to work on machines without /dev/random.
**
**      Revision 1.13  2003/05/20 19:18:00  dgm
**      Comment changes only.
**
**      Revision 1.12  2003/05/15 12:30:39  dgm
**      include netinet/in.h
**
**      Revision 1.11  2003/05/13 11:38:53  dgm
**      Patches by Ken Murchison <ken@oceana.com> to clean up build process.
**
**      Revision 1.10  2003/05/06 12:09:12  dgm
**      Applied patches by Ken Murchison <ken@oceana.com> to add SSL
**      support and remove old base64 functions.
**
**      Revision 1.9  2003/04/16 12:19:29  dgm
**      Added support for syslog configuration.
**      Added base64 routine prototypes that I previously forgot.
**
**      Revision 1.8  2003/03/19 13:24:50  dgm
**      Applied patch by Devrim Seral  <devrim@gazi.edu.tr> to allow
**      the default configfile to be configurable via a configure script.
**      (Lots of configures in that sentence, huh?)
**
**      Revision 1.7  2003/02/20 12:40:08  dgm
**      Added UNSELECT support.
**
**      Revision 1.6  2003/02/19 13:03:35  dgm
**      Added LITERAL_PASSWORD and NON_LITERAL_PASSWORD definitions.
**
**      Revision 1.5  2003/01/22 15:33:53  dgm
**      Changed Get_Server_sd() function prototype to reflect the addition of
**      the literal password flag.
**
**      Revision 1.4  2002/12/19 21:41:32  dgm
**      Added support for global configuration.
**
**      Revision 1.3  2002/08/30 13:21:42  dgm
**      Added total client logins counter to IMAPCounter struct
**
**      Revision 1.2  2002/08/29 16:33:46  dgm
**      Added CountTime field to struct IMAPCounter.
**      Removed #define for max number of open file descriptors since
**      we now determine rlimit dynamically instead.
**      Added POLL_TIMEOUT stuff.
**
**      Revision 1.1  2002/07/03 11:21:12  dgm
**      Initial revision
**
*/


#ifndef __IMAPPROXY_H
#define __IMAPPROXY_H

#include <netdb.h>
#include <pthread.h>
#include <netinet/in.h>
#include <time.h>
#include "config.h"

#if HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <limits.h>
#endif


/* 
 * Common definitions 
 */
#define PGM                     "in.imapproxyd"
#define IMAP_UNTAGGED_OK        "* OK "           /* untagged OK response    */
#define IMAP_TAGGED_OK          "1 OK "           /* tagged OK response      */
#define BUFSIZE                 8192              /* default buffer size     */
#define MAX_CONN_BACKLOG        5                 /* tcp connection backlog  */
#define MAXTAGLEN               256               /* max IMAP tag length     */
#define MAXMAILBOXNAME          512               /* max mailbox name length */
#define MAXUSERNAMELEN          256               /* max username length     */
#define MAXPASSWDLEN            8192              /* max passwd length       */
#define POLL_TIMEOUT_MINUTES    30                /* Poll timeout in minutes */
#define POLL_TIMEOUT            (POLL_TIMEOUT_MINUTES * 60000)
#define SELECT_BUF_SIZE         BUFSIZE           /* max length of a SELECT  */
						  /* string we can cache     */
#define SELECT_CACHE_EXP        10                /* # of seconds before we  */
                                                  /* expire a SELECT cache   */
#define SELECT_STATUS_BUF_SIZE  256               /* size of select status   */

#ifndef DEFAULT_CONFIG_FILE
#define DEFAULT_CONFIG_FILE     "/etc/imapproxy.conf"
#endif
#ifndef DEFAULT_PID_FILE
#define DEFAULT_PID_FILE       "/var/run/imapproxy.pid"
#endif

#define LITERAL_PASSWORD        1
#define NON_LITERAL_PASSWORD    0
#define UNSELECT_SUPPORTED      1
#define UNSELECT_NOT_SUPPORTED  0
#define STARTTLS_SUPPORTED      1
#define STARTTLS_NOT_SUPPORTED  0
#define LOGIN_DISABLED          1
#define LOGIN_NOT_DISABLED      0


#define DEFAULT_SERVER_CONNECT_RETRIES	10
#define DEFAULT_SERVER_CONNECT_DELAY	5

/*
 * One IMAPServerDescriptor will be globally allocated such that each thread
 * can save the time of doing host lookups, service lookups, and filling
 * in the sockaddr_storage struct.
 */
struct IMAPServerDescriptor
{
    struct addrinfo *airesults; /* IMAP server info (top of addrinfo
				   list from getaddrinfo() */
    struct addrinfo *srv;	/* IMAP server active socket info */
};


/*
 * IMAPSelectCaches provide for caching of SELECT output from an IMAP server
 */
struct IMAPSelectCache
{
    time_t ISCTime;
    char MailboxName[ MAXMAILBOXNAME ];
    char SelectString[ SELECT_BUF_SIZE ];
    char SelectStatus[ SELECT_STATUS_BUF_SIZE ];
};


/*
 * IMAPConnectionDescriptors contain the info needed to communicate on an
 * IMAP connection.
 */
struct IMAPConnectionDescriptor
{
    int sd;                          /* socket descriptor                    */
#if HAVE_LIBSSL
    SSL *tls;                        /* TLS connection context               */
#endif
    struct IMAPSelectCache ISC;      /* Cached SELECT data                   */
    struct IMAPConnectionContext *ICC; /* backreference the ICC */
    unsigned int reused;             /* Was the connection reused?           */
};


/*
 * IMAPTransactionDescriptors facilitate multi-line buffered reads from
 * IMAP servers and clients.
 */
struct IMAPTransactionDescriptor
{
    struct IMAPConnectionDescriptor *conn;
    char ReadBuf[ BUFSIZE ];         /* Read Buffer                          */
    unsigned int BytesInReadBuffer;  /* bytes left in read buffer            */
    unsigned int ReadBytesProcessed; /* bytes already processed in read buf  */
    unsigned int LiteralBytesRemaining; /* num of bytes left as literal     */
    unsigned char NonSyncLiteral;    /* rfc2088 alert flag                   */
    unsigned char MoreData;          /* flag to tell caller "more data"      */
    unsigned char TraceOn;           /* trace this transaction?              */
};


/*
 * IMAPConnectionContext structures are used to cache connection info on
 * a per-user basis.
 */
struct IMAPConnectionContext
{
    struct IMAPConnectionDescriptor *server_conn;
    char username[MAXUSERNAMELEN];      /* username connected on this sd     */
    char hashedpw[16];                  /* md5 hash copy of password         */
    time_t logouttime;                  /* time the user logged out last     */
    struct IMAPConnectionContext *next; /* linked list next pointer          */
};


/*
 * One ProxyConfig structure will be used globally to keep track of
 * configurable options.  All of these options are set by reading values
 * from the global config file except for support_unselect.  That's set
 * based on the CAPABILITY string from the real IMAP server.
 */
struct ProxyConfig
{
    char *listen_port;         	              /* port we bind to */
    char *listen_addr;                        /* address we bind to */
    char *server_hostname;                    /* server we proxy to */
    char *server_port;                        /* port we proxy to */
    unsigned int server_connect_retries;      /* connect retries to IMAP server */
    unsigned int server_connect_delay;	      /* delay between connection retry rounds */
    unsigned int cache_size;                  /* number of cache slots */
    unsigned int cache_expiration_time;       /* cache exp time in seconds */
    unsigned int send_tcp_keepalives;         /* flag to send keepalives */
    unsigned int enable_select_cache;         /* flag to enable select cache */
    unsigned int foreground_mode;             /* flag to enable fg mode */
    char *proc_username;                      /* username to run as */
    char *proc_groupname;                     /* groupname to run as */
    char *stat_filename;                      /* mmap()ed stat filename */
    char *protocol_log_filename;              /* global trace filename */
    char *syslog_facility;                    /* syslog log facility */
    char *syslog_prioritymask;                /* syslog priority mask */
    char *tls_ca_file;                        /* file with CA certs */
    char *tls_ca_path;                        /* path to directory CA certs */
    char *tls_cert_file;                      /* file with client cert */
    char *tls_key_file;                       /* file with client priv key */
    char *tls_ciphers;                        /* TLS Cipher suite */
    unsigned int tls_verify_server;           /* flag to require server cert validation */
    unsigned int tls_no_tlsv1;                /* flag to disable TLSv1 */
    unsigned int tls_no_tlsv1_1;              /* flag to disable TLSv1.1 */
    unsigned int tls_no_tlsv1_2;              /* flag to disable TLSv1.2 */
    unsigned int force_tls;                   /* flag to force TLS */
    unsigned int enable_admin_commands;       /* flag to enable admin cmds */
    unsigned char support_unselect;           /* unselect support flag */
    unsigned char support_starttls;           /* starttls support flag */
    unsigned char login_disabled;             /* login disabled flag */
    char *chroot_directory;                   /* chroot(2) into this dir */
    char *preauth_command;                    /* arbitrary pre-authentication command */
    char *auth_sasl_plain_username;           /* authentication username under SASL PLAIN */
    char *auth_sasl_plain_password;           /* authentication password under SASL PLAIN */
    char *auth_shared_secret;                 /* REQUIRED shared secret in leiu of a user password when using LOGIN command with SASL PLAIN authentication */
};


/*
 * One IMAPCounter structure will be used globally to keep track of
 * several different things that we want to keep a count of, purely for
 * diagnostic, or usage tracking purposes.
 *
 * IMPORTANT NOTE: No attempt is made to guarantee that these counters
 * will be completely accurate.  No mutex is ever taken out when these
 * counters are updated.  This was done for performance -- these numbers
 * aren't considered important enough to waste time locking a mutex to
 * guarantee their accuracy.
 */
struct IMAPCounter
{
    time_t StartTime;
    time_t CountTime;
    unsigned int CurrentClientConnections;
    unsigned int PeakClientConnections;
    unsigned int InUseServerConnections;
    unsigned int PeakInUseServerConnections;
    unsigned int RetainedServerConnections;
    unsigned int PeakRetainedServerConnections;
    unsigned int TotalClientConnectionsAccepted;
    unsigned int TotalClientLogins;
    unsigned int TotalServerConnectionsCreated;
    unsigned int TotalServerConnectionsReused;
    unsigned int TotalSelectCommands;
    unsigned int SelectCacheHits;
    unsigned int SelectCacheMisses;
};

   

typedef struct IMAPServerDescriptor ISD_Struct;
typedef struct IMAPTransactionDescriptor ITD_Struct;
typedef struct IMAPConnectionDescriptor ICD_Struct;
typedef struct IMAPConnectionContext ICC_Struct;
typedef struct IMAPCounter IMAPCounter_Struct;
typedef struct ProxyConfig ProxyConfig_Struct;
typedef struct IMAPSelectCache ISC_Struct;

/*
 * Function prototypes for external entry points.
 */
extern int IMAP_Write( ICD_Struct *, const void *, int );
extern int IMAP_Read( ICD_Struct *, void *, int );
extern int IMAP_Line_Read( ITD_Struct * );
extern int IMAP_Literal_Read( ITD_Struct * );
extern void HandleRequest( int );
extern char *memtok( char *, char *, char ** );
extern int imparse_isatom( const char * );
extern ICD_Struct *Get_Server_conn( char *, char *, const char *, const char *, unsigned char, char * );
extern void ICC_Logout( ICC_Struct * );
extern void ICC_Recycle( unsigned int );
extern void ICC_Recycle_Loop( void );
extern void LockMutex( pthread_mutex_t * );
extern void UnLockMutex( pthread_mutex_t * );
extern void SetDefaultConfigValues(ProxyConfig_Struct *);
extern void SetConfigOptions( char * );
extern void SetLogOptions( void );
extern int Handle_Select_Command( ITD_Struct *, ITD_Struct *, ISC_Struct *, char *, int );
extern unsigned int Is_Safe_Command( char *Command );
extern void Invalidate_Cache_Entry( ISC_Struct * );
extern int atoui( const char *, unsigned int * );


#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16	/* When would it ever be different? */
#endif
extern void ssl_thread_setup(const char * fn);


#endif /* __IMAPPROXY_H */


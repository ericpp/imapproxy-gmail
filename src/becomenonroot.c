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
**	becomenonroot.c
**
**  Abstract:
**
**	Routine to switch the unix uid of a running process from root to
**	some other non-zero uid.
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
**      Revision 1.4  2005/06/15 12:10:12  dgm
**      Conditionally include unistd.h.  Include config.h.  Patch
**      by Jarno Huuskonen to drop any supplemental group memberships.
**      Patch by Dave Steinberg and Jarno Huuskonen to allow chroot.
**
**      Revision 1.3  2003/05/20 18:42:39  dgm
**      comment changes only
**
**      Revision 1.2  2002/12/17 14:26:17  dgm
**      Added suport for global configuration structure.
**
**      Revision 1.1  2002/08/29 16:24:31  dgm
**      Initial revision
**
*/

#include <config.h>

#include <sys/types.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "imapproxy.h"

extern ProxyConfig_Struct PC_Struct;


/*++
 * Function:    BecomeNonRoot
 *
 * Purpose:     If we are running as root, attempt to change that.
 *
 * Parameters:  nada
 *
 * Returns:     0 on success
 *              -1 on failure
 *
 * Authors:     Dave McMurtrie <davemcmurtrie@hotmail.com>
 *
 * Notes:       Relies on global copy of ProxyConfig_Struct "PC_Struct".
 *              Also worth mentioning that instead of just becoming non-root
 *              this function is now also responsible for chown()ing
 *              the global statistics file.  I had to choose
 *              between doing a passwd and group lookup twice (and further
 *              cluttering main) or doing the chown here where it
 *              doesn't logically belong.  I chose to put it here, but at
 *              least I documented it...
 *
 *              In addition to becoming non-root, this function now also
 *              does a chroot() if so configured.  Soon I'll rename this
 *              function to something more fitting...
 *--
 */
extern int BecomeNonRoot( void )
{
    char *fn = "BecomeNonRoot()";
    struct passwd *pwent;                    /* ptr to a passwd file entry */
    struct group *gp;                        /* ptr to a group file entry */
    uid_t newuid;                            /* uid we want to run as */
    gid_t newgid;                            /* gid we want to run as */
    
    if ((pwent = getpwnam( PC_Struct.proc_username )) == NULL)
    {
	syslog(LOG_WARNING, "%s: getpwnam(%s) failed.", 
	       fn, PC_Struct.proc_username);
	return(-1);
    }
    else
    {
	newuid = pwent->pw_uid;
    }
    
    /*
     * Since the whole purpose here is to not run as root, make sure that
     * we don't get UID 0 back for username.
     */
    if ( newuid == 0 )
    {
	syslog( LOG_ERR, "%s: getpwnam returned UID 0 for '%s'.", 
		fn, PC_Struct.proc_username );
	return(-1);
    }
    
    if ((gp = getgrnam( PC_Struct.proc_groupname )) == NULL)
    {
	syslog(LOG_WARNING, "%s: getgrnam(%s) failed.", 
	       fn, PC_Struct.proc_groupname);
	return(-1);
    }
    else
    {
	newgid = gp->gr_gid;
    }
    
    /*
     * The chown() call gets stuck here.  I hate it, but 
     * once in a while there are going to be things in life that I hate.
     */
    if ( chown( PC_Struct.stat_filename, newuid, newgid ) < 0 )
    {
	syslog( LOG_WARNING, "%s: chown() failed to set ownership of file '%s' to '%s:%s': %s", fn, PC_Struct.stat_filename, PC_Struct.proc_username, PC_Struct.proc_groupname, strerror( errno ) );
	return( -1 );
    }
    

    /*
     * Now the whole reason this function exists...  setgid and setuid.
     *
     * Patch by Jarno Huuskonen -- also drop any supplementary groups.
     */

    syslog( LOG_INFO, "%s: Process will run as uid %d (%s) and gid %d (%s).",
	    fn, newuid, PC_Struct.proc_username, 
	    newgid, PC_Struct.proc_groupname );
    
    if ( setgroups( 0, NULL ) < 0 )
    {
	syslog( LOG_WARNING, "%s: setgroups() failed: %s", fn, strerror( errno ) );
	return( -1 );
    }
    
    if ((setgid(newgid)) < 0 )
    {
	syslog(LOG_WARNING, "%s: setgid(%d) failed: %s", fn, 
	       newgid, strerror(errno));
	return(-1);
    }

    /*
     * Patch originally by Dave Steinberg, and later modified by
     * Jarno Huuskonen -- chroot() if so configured.
     */
    if ( PC_Struct.chroot_directory ) 
    {
	if ( chroot( PC_Struct.chroot_directory ) < 0 || chdir( "/" ) < 0 ) 
	{
	    syslog( LOG_WARNING, "%s: chroot(%s) failed: %s", fn, PC_Struct.chroot_directory, strerror( errno ) );
	    return( -1 );
	}
	
	syslog( LOG_INFO, "%s: Process chrooted in %s", fn, PC_Struct.chroot_directory );
    }
    
    if ((setuid(newuid)) < 0 )
    {
	syslog(LOG_WARNING,"%s: setuid(%d) failed: %s", fn, 
	       newuid, strerror(errno));
	return(-1);
    }
    
    return(0);
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

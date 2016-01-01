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
**	common.h
**
**  Abstract:
**
**	Function declarations for public entry points to common library
**	functions.
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
**      Revision 1.12  2010/02/20 17:15:21  dave64
**      updated version to 1.2.7
**
**      Revision 1.11  2009/01/12 13:22:17  dave64
**      Updated versiopn to 1.2.7rc2
**
**      Revision 1.10  2008/10/20 13:21:05  dave64
**      updated version to 1.2.7rc1
**
**      Revision 1.9  2008/01/28 13:11:55  dave64
**      updated version to 1.2.6
**
**      Revision 1.8  2007/11/15 11:13:13  dave64
**      updated version to 1.2.6rc2.
**
**      Revision 1.7  2007/05/31 12:13:30  dave64
**      Updated version string to 1.2.6rc1
**
**      Revision 1.6  2007/01/30 15:19:29  dave64
**      Updated version string to 1.2.5.
**
**      Revision 1.5  2006/10/03 12:21:54  dave64
**      Updated version string to 1.2.5rc2.
**
**      Revision 1.4  2006/02/16 18:32:30  dave64
**      Added IMAP_PROXY_VERSION patch by Matt Selsky.
**
**      Revision 1.3  2003/05/20 19:14:10  dgm
**      Comment changes only.
**
**      Revision 1.2  2002/12/19 21:43:35  dgm
**      modified parameter list of becomenonroot to support global config.
**
**      Revision 1.1  2002/08/29 16:31:19  dgm
**      Initial revision
**
*/

#ifndef __COMMON_H
#define __COMMON_H


#define HASH_TABLE_SIZE         1024
#define IMAP_PROXY_VERSION      "1.2.8 [SVN]"

/*
 * Misc. function prototypes.
 */
extern int BecomeNonRoot( void );
extern unsigned int Hash(char *, unsigned int );


#endif /* COMMON_H */




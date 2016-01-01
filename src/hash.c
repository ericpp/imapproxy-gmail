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
**      hash.c
**	Hashing routines
**
**  Abstract:
**
**	Routines to provide an easy interface to hashing functions.
**
**  Authors:
**
**      Ben Carter
**
**  Version:
**
**      $Id$
**
**  Modification History:
**
**      $Log$
**
**      Revision 1.2  2003/05/20 18:43:52  dgm
**      comment changes only.
**
**      Revision 1.1  2002/08/29 16:27:23  dgm
**      Initial revision
**
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "common.h"

/*++
 * Function:	Hash
 *
 * Purpose:	Generate a hash key.
 *
 * Parameters:	pointer to char -- input key
 *		unsigned int -- maximum length of the input key
 *		unsigned int -- hash table size
 *
 * Returns:	unsigned int -- hash key
 *
 * Authors:	bhc
 *--
 */
unsigned int Hash(char *Input_Key, unsigned int	Table_Size )
{
  unsigned int	i;
  unsigned int  Size;
  unsigned int	Longwords;
  unsigned int	*I_Pointer;
  unsigned int	Hash_Value=0;
  char	Hash_Buffer[1024];
  Size = strlen( Input_Key );

  if ( Size > sizeof Hash_Buffer )
  {
    syslog(LOG_ERR, "Hash(): Maximum of %d for '%s' exceeds architectural limit of %d", Size, Input_Key, sizeof Hash_Buffer );
    exit(1);
  }

  Longwords = ( ( Size + 3 ) / 4 );
  memset( Hash_Buffer, 0, Longwords*4 );
  memcpy( Hash_Buffer, Input_Key, Size );
  I_Pointer = (unsigned int *) Hash_Buffer;
  
  for ( i=0; i<Longwords; i++ )
  {
    Hash_Value = Hash_Value + *I_Pointer;
    I_Pointer++;
  }
  
  Hash_Value = Hash_Value + Size;
  
  Hash_Value = Hash_Value % Table_Size;
  
  return(Hash_Value);
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

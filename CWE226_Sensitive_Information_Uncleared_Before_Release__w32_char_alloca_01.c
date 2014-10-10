/*
 * @description
 * CWE: 226 Sensitive Information Uncleared Before Release
 * Sinks: alloca
 *    GoodSink: Clear the password buffer before releasing the memory from the stack
 *    BadSink : Release password from the stack without first clearing the buffer
 * Flow Variant: 01 Baseline
 *
 * */

#define _XOPEN_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <alloca.h>

#define ALLOCA alloca
#define KEY "ab"

void CWE226_Sensitive_Information_Uncleared_Before_Release__w32_char_alloca_01_bad()
{
    {
        char * password = (char *)ALLOCA(100*sizeof(char));
	char * epasswd = (char *)ALLOCA(100*sizeof(char));
        size_t passwordLen = 0;

        /* Initialize password */
        password[0] = '\0';
        if (fgets(password, 100, stdin) == NULL)
        {
            printf("fgets() failed\n");
            /* Restore NUL terminator if fgets fails */
            password[0] = '\0';
        }
        /* Remove the carriage return from the string that is inserted by fgets() */
        passwordLen = strlen(password);
        if (passwordLen > 0)
        {
            password[passwordLen-1] = '\0';
        }
        /* Use the password in LogonUser() to establish that it is "sensitive" */
	/* ELISA: for Linux we use crypt to establish that it is sensitive */
       
 	epasswd = crypt (password, KEY);
        if (epasswd == NULL) {
		printf ("crypt error\n");
		exit (1);
	}
	// printf ("passwd=%s, epasswd=%s\n",  password, epasswd);


        /* FLAW: Release password from the stack without first clearing the buffer */
    }
}

static void good1()
{
    {
        char * password = (char *)ALLOCA(100*sizeof(char));
	char * epasswd = (char *)ALLOCA(100*sizeof(char));

        size_t passwordLen = 0;
        /* Initialize password */
        password[0] = '\0';
        if (fgets(password, 100, stdin) == NULL)
        {
            printf("fgets() failed\n");
            /* Restore NUL terminator if fgets fails */
            password[0] = '\0';
        }
        /* Remove the carriage return from the string that is inserted by fgets() */
        passwordLen = strlen(password);
        if (passwordLen > 0)
        {
            password[passwordLen-1] = '\0';
        }
        /* Use the password in LogonUser() to establish that it is "sensitive" */
       
       epasswd = crypt (password, KEY);
       if (epasswd == NULL) {
		printf ("crypt error\n");
		exit (1);
	}
	// printf ("passwd=%s, epasswd=%s\n",  password, epasswd);
	
	passwordLen = strlen(password);
        /* FIX: Clear password prior to release from stack */
        memset(password, 0, passwordLen * sizeof(char));
	// printf ("Limpio: %c %c %c\n", password[0], password[1], password[3]);
    }
}

void CWE226_Sensitive_Information_Uncleared_Before_Release__w32_char_alloca_01_good()
{
    good1();
}


int main(int argc, char * argv[])
{
    printf("Calling good()...\n");
    CWE226_Sensitive_Information_Uncleared_Before_Release__w32_char_alloca_01_good();
    printf("Finished good()\n");
    printf("Calling bad()...\n");
    CWE226_Sensitive_Information_Uncleared_Before_Release__w32_char_alloca_01_bad();
    printf("Finished bad()\n");
    return 0;
}


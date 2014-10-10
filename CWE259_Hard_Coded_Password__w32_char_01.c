/*
 * @description
 * CWE: 259 Use of Hard-coded Password
 * BadSource:  Use a hardcoded password
 * GoodSource: Read the password from the console
 * Sink:
 *    BadSink : Authenticate the user using LogonUserA()
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
#define PASSWORD "ABCD1234!"
#define KEY "ab"

void CWE259_Hard_Coded_Password__w32_char_01_bad()
{
    char * password;
    char passwordBuffer[100] = "";
    char * epasswd = (char *)ALLOCA(100*sizeof(char));

    password = passwordBuffer;
    /* FLAW: Use a hardcoded password */
    strcpy(password, PASSWORD);
    {
        /* POTENTIAL FLAW: Attempt to login user with password from the source (which may be hardcoded) */
	epasswd = crypt (password, KEY);
	if (epasswd == NULL) {
		printf ("crypt error\n");
		exit (1);
	}
	// printf ("passwd=%s, epasswd=%s\n",  password, epasswd);
    }
}

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * password;
    char passwordBuffer[100] = "";
    char * epasswd = (char *)ALLOCA(100*sizeof(char));

    password = passwordBuffer;
    {
        size_t passwordLen = 0;
        /* FIX: Read the password from the console */
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
    }
    {
    	epasswd = crypt (password, KEY);
	if (epasswd == NULL) {
		printf ("crypt error\n");
		exit (1);
	}
	// printf ("passwd=%s, epasswd=%s\n",  password, epasswd);
    }
}

void CWE259_Hard_Coded_Password__w32_char_01_good()
{
    goodG2B();
}


int main(int argc, char * argv[])
{
    printf("Calling good()...\n");
    CWE259_Hard_Coded_Password__w32_char_01_good();
    printf("Finished good()\n");
    printf("Calling bad()...\n");
    CWE259_Hard_Coded_Password__w32_char_01_bad();
    printf("Finished bad()\n");
    return 0;
}


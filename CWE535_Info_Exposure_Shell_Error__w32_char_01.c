/*
 * @description
 * CWE: 535 Information Exposure Through Shell Error Message
 * Sinks:
 *    GoodSink: Write to stderr, but do not write the password
 *    BadSink : Write to stderr and include the password
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

void CWE535_Info_Exposure_Shell_Error__w32_char_01_bad()
{
    {
        char password[100] = "";
	char * epasswd = (char *)ALLOCA(100*sizeof(char));

        size_t passwordLen = 0;
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
	printf ("passwd=%s, epasswd=%s\n",  password, epasswd);

        /* FLAW: Write sensitive data to stderr */
        fprintf(stderr, "User attempted access with password: %s\n", password);
    }
}

static void good1()
{
    {
        char password[100] = "";
	char * epasswd = (char *)ALLOCA(100*sizeof(char));

        size_t passwordLen = 0;
        char * username = "User";
        char * domain = "Domain";
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
	printf ("passwd=%s, epasswd=%s\n",  password, epasswd);
								

        /* FIX: Do not write sensitive data to stderr */
        fprintf(stderr, "User attempted access\n");
    }
}

void CWE535_Info_Exposure_Shell_Error__w32_char_01_good()
{
    good1();
}


int main(int argc, char * argv[])
{
    printf("Calling good()...\n");
    CWE535_Info_Exposure_Shell_Error__w32_char_01_good();
    printf("Finished good()\n");
    printf("Calling bad()...\n");
    CWE535_Info_Exposure_Shell_Error__w32_char_01_bad();
    printf("Finished bad()\n");
    return 0;
}

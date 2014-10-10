/*
 * @description
 * CWE: 23 Relative Path Traversal
 * BadSource: environment Read input from an environment variable
 * GoodSource: Use a fixed file name
 * Sink: fopen
 *    BadSink : Open the file named in data using fopen()
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

#define BASEPATH "/tmp/"
#define ENV_VARIABLE "ADD"

void bad()
{
    char * data;
    char dataBuffer[FILENAME_MAX] = BASEPATH;
    data = dataBuffer;
        {
            /* Append input from an environment variable to data */
            size_t dataLen = strlen(data);
            char * environment = getenv(ENV_VARIABLE);
            /* If there is data in the environment variable */
            if (environment != NULL)
            {
                /* POTENTIAL FLAW: Read data from an environment variable */
                strncat(data+dataLen, environment, FILENAME_MAX-dataLen-1);
            }
        }
    {
        FILE *pFile = NULL;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        pFile = fopen(data, "wb+");
        if (pFile != NULL)
        {
            fclose(pFile);
        }
    }
}

static void goodG2B1()
{
    char * data;
    char dataBuffer[FILENAME_MAX] = BASEPATH;
    data = dataBuffer;
        /* FIX: Use a fixed file name */
        strcat(data, "file.txt");
    {
        FILE *pFile = NULL;
        /* POTENTIAL FLAW: Possibly opening a file without validating the file name or path */
        pFile = fopen(data, "wb+");
        if (pFile != NULL)
        {
            fclose(pFile);
        }
    }
}

void good()
{
    goodG2B1();
}


int main(int argc, char * argv[])
{
    printf("Calling good()...\n");
    good();
    printf("Finished good()\n");
    printf("Calling bad()...\n");
    bad();
    printf("Finished bad()\n");
    
    return 0;
}


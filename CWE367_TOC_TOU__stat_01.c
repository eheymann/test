/*
 * @description
 * CWE: 367 Time-of-Check Time-Of-Use Race Condition
 * Sinks: stat
 *    GoodSink: Open the file without checking the status information
 *    BadSink : Get status information on file using stat(), open, write to, and close the file
 * Flow Variant: 01 Baseline
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define STAT stat
#define OPEN open
#define WRITE write
#define CLOSE close

#define BAD_SINK_STRING "Bad Sink..."
#define GOOD_SINK_STRING "Good Sink..."


void CWE367_TOC_TOU__stat_01_bad()
{
    {
        char filename[100] = "";
        struct STAT statBuffer;
        int fileDesc = -1;
        if (fgets(filename, 100, stdin) == NULL)
        {
            printf("fgets() failed\n");
            /* Restore NUL terminator if fgets fails */
            filename[0] = '\0';
        }
        if (strlen(filename) > 0)
        {
            filename[strlen(filename)-1] = '\0'; /* remove newline */
        }
        /* FLAW: Open and write to the file after checking the status information */
        if (STAT(filename, &statBuffer) == -1)
        {
            exit(1);
        }
        fileDesc  = OPEN(filename, O_RDWR);
        if (fileDesc == -1)
        {
            exit(1);
        }
        if (WRITE(fileDesc, BAD_SINK_STRING, strlen(BAD_SINK_STRING)) == -1)
        {
            exit(1);
        }
        if (fileDesc != -1)
        {
            CLOSE(fileDesc);
        }
    }
}


static void good1()
{
    {
        char filename[100] = "";
        int fileDesc = -1;
        if (fgets(filename, 100, stdin) == NULL)
        {
            printf("fgets() failed\n");
            /* Restore NUL terminator if fgets fails */
            filename[0] = '\0';
        }
        if (strlen(filename) > 0)
        {
            filename[strlen(filename)-1] = '\0'; /* remove newline */
        }
        /* FIX: Open the file without checking the status information */
        fileDesc  = OPEN(filename, O_RDWR);
        if (fileDesc == -1)
        {
            exit(1);
        }
        if (WRITE(fileDesc, GOOD_SINK_STRING, strlen(GOOD_SINK_STRING)) == -1)
        {
            exit(1);
        }
        if (fileDesc != -1)
        {
            CLOSE(fileDesc);
        }
    }
}

void CWE367_TOC_TOU__stat_01_good()
{
    good1();
}


int main(int argc, char * argv[])
{
    printf("Calling good()...\n");
    CWE367_TOC_TOU__stat_01_good();
    printf("Finished good()\n");
    printf("Calling bad()...\n");
    CWE367_TOC_TOU__stat_01_bad();
    printf("Finished bad()\n");
    return 0;
}


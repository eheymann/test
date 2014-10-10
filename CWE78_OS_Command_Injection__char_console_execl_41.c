/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: console Read input from the console
 * GoodSource: Fixed string
 * Sink: execl
 *    BadSink : execute command with execl
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#define EXECL execl
#define COMMAND_INT_PATH "/bin/sh"
//#define COMMAND_ARG1 "/bin/ls"
#define COMMAND_ARG1 "script1"
#define COMMAND_ARG2 "-la"
#define COMMAND_ARG3 data


void CWE78_OS_Command_Injection__char_console_execl_41_badSink(char * data)
{
    /* execl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
//    printf ("Comando a ejecutar: %s %s %s\n", COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3);
    system (data);
//    EXECL (COMMAND_INT_PATH, COMMAND_INT_PATH, COMMAND_ARG1, COMMAND_ARG3, NULL);
}

void CWE78_OS_Command_Injection__char_console_execl_41_bad()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    {
        /* Read input from the console */
        size_t dataLen = strlen(data);
        /* if there is room in data, read into it from the console */
        if (100-dataLen > 1)
        {
            /* POTENTIAL FLAW: Read data from the console */
            if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL)
            {
                /* The next few lines remove the carriage return from the string that is
                 * inserted by fgets() */
                dataLen = strlen(data);
                if (dataLen > 0 && data[dataLen-1] == '\n')
                {
                    data[dataLen-1] = '\0';
                }
            }
            else
            {
                printf("fgets() failed\n");
                /* Restore NUL terminator if fgets fails */
                data[dataLen] = '\0';
            }
        }
    }
    CWE78_OS_Command_Injection__char_console_execl_41_badSink(data);
}



void CWE78_OS_Command_Injection__char_console_execl_41_goodG2BSink(char * data)
{
    /* execl - specify the path where the command is located */
    /* POTENTIAL FLAW: Execute command without validating input possibly leading to command injection */
    EXECL(COMMAND_INT_PATH, COMMAND_INT_PATH, "-c", COMMAND_ARG1, COMMAND_ARG2, COMMAND_ARG3, NULL);
}

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Append a fixed string to data (not user / external input) */
    strcat(data, "*.*");
    CWE78_OS_Command_Injection__char_console_execl_41_goodG2BSink(data);
}

void CWE78_OS_Command_Injection__char_console_execl_41_good()
{
    goodG2B();
}



int main(int argc, char * argv[])
{
    srand( (unsigned)time(NULL) );
 //   printf("Calling good()...\n");
 //   CWE78_OS_Command_Injection__char_console_execl_41_good();
 //   printf("Finished good()\n");
    printf("Calling bad()...\n");
    CWE78_OS_Command_Injection__char_console_execl_41_bad();
    printf("Finished bad()\n");
    return 0;
}

/* good esta en comentario ya que tiene un execl y no retorna.
bad necesita input por stdin. 
/bin/sh no funciona sin el -c option, y con el -c acepta solo un argumento, asi que es problematico para un inject.
I'd like the behavior of /bin/sh script1 `echo abc`
*/

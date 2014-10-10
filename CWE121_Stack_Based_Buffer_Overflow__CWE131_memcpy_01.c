/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Allocate memory without using sizeof(int)
 * GoodSource: Allocate memory using sizeof(int)
 * Sink: memcpy
 *    BadSink : Copy array to data using memcpy()
 * Flow Variant: 01 Baseline
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>

#define ALLOCA alloca

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_01_bad()
{
    int * data;
    data = NULL;
    /* FLAW: Allocate memory without using sizeof(int) */
    data = (int *)ALLOCA(10);
    {
        int source[10] = {0};
        /* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */
        memcpy(data, source, 10*sizeof(int));
        printf("%d\n", data[0]);
    }
}


/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    int * data;
    data = NULL;
    /* FIX: Allocate memory using sizeof(int) */
    data = (int *)ALLOCA(10*sizeof(int));
    {
        int source[10] = {0};
        /* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */
        memcpy(data, source, 10*sizeof(int));
	printf("%d\n", data[0]);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_01_good()
{
    goodG2B();
}


int main(int argc, char * argv[])
{
    srand( (unsigned)time(NULL) );
    printf("Calling good()...\n");
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_01_good();
    printf("Finished good()\n");
    printf("Calling bad()...\n");
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_01_bad();
    printf("Finished bad()\n");
    return 0;
}


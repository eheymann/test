/*
 * @description
 * CWE: 190 Integer Overflow
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Set data to a small, non-zero number (two)
 * Sinks: add
 *    GoodSink: Ensure there will not be an overflow before adding 1 to data
 *    BadSink : Add 1 to data, which can cause an overflow
 * Flow Variant: 01 Baseline
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>


void CWE190_Integer_Overflow__char_fscanf_add_01_bad()
{
    char data;
    data = ' ';
    /* POTENTIAL FLAW: Use a value input from the console */
    scanf ("%c", &data);
    {
        /* POTENTIAL FLAW: Adding 1 to data could cause an overflow */
        char result = data + 1;
        printf("%d\n", result);
    }
}

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char data;
    data = ' ';
    /* FIX: Use a small, non-zero value that will not cause an overflow in the sinks */
    data = 2;
    {
        /* POTENTIAL FLAW: Adding 1 to data could cause an overflow */
        char result = data + 1;
	printf("%d\n", result);
    }
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    char data;
    data = ' ';
    /* POTENTIAL FLAW: Use a value input from the console */
    scanf ("%c", &data);
    printf ("char = %d\n", data);
    /* FIX: Add a check to prevent an overflow from occurring */
    if (data < CHAR_MAX)
    {
        char result = data + 1;
	printf ("Char Max es: %d\n", CHAR_MAX);
	printf("%d\n", result);
    }
    else
    {
        printf("data value is too large to perform arithmetic safely.\n");
    }
}

void CWE190_Integer_Overflow__char_fscanf_add_01_good()
{
    goodG2B();
    goodB2G();
}


int main(int argc, char * argv[])
{
    printf("Calling good()...\n");
    CWE190_Integer_Overflow__char_fscanf_add_01_good();
    printf("Finished good()\n");
    printf("Calling bad()...\n");
    CWE190_Integer_Overflow__char_fscanf_add_01_bad();
    printf("Finished bad()\n");
    return 0;
}


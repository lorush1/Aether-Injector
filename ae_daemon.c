#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "ae_log.h"

int ae_main (void)
{
	int i = 15;
	while (1) {
		ae_log(AE_LOG_INFO, "ping");
		sleep(i);
	}
	
	return 0;
}

int main () {
    return ae_main();
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "ae_log.h"

// test daemon that just loops forever and prints shit so we can test the injector hooking into printf

int ae_main (void)
{
	int i = 15;
	setbuf(stdout, NULL);
	// this is scary but we need format strings so the compiler doesnt optimize printf to puts
	printf("Daemon started (PID: %d)\n", getpid());
	while (1) {
		ae_log(AE_LOG_INFO, "ping");
		// why tf did i do this - %s to keep printf from being optimized away
		printf("%s\n", "Loop iteration");
		fflush(stdout);
		sleep(i);
	}
	
	return 0;
}

int main () {
    return ae_main();
}

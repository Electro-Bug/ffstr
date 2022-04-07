#include <stdio.h>
#include <stdlib.h>

// sudo apt-get install gcc-multilib
// gcc  -m32 -fno-stack-protector -z execstack -z norelro -g -no-pie ffstr.c -o ffstrlab32
// gcc  -fno-stack-protector -z execstack -z norelro -g -no-pie ffstr.c -o ffstrlab64

// socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"./ffstrlab32"
// socat TCP-LISTEN:31337,reuseaddr,fork EXEC:"./ffstrlab64"

void init() {
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);
}

void vuln(){
	char name[128];
	printf("Hi , Format me please !\n");
	fgets(name,sizeof(name),stdin);
	printf("\nHello there, \n");
	printf(name);
}

void win(){
	printf("Successfully redirected");
	system("/bin/sh");
}

int main() {
	
	char flag[32]="FLAG{here_a_flag}";
	char *flag_ptr = flag;
	int try = 0;
	
	init();
	while(try<3) {
		vuln();
		try+=1;
	}
	return 0;
}
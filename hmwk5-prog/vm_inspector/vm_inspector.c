#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>


#define CHECK_BIT(var, pos) (((var) & (1<<(pos))) >> (pos))

#define PAGE_SHIFT		12
#define PAGE_SIZE		4096
#define	PGDIR_SHIFT		21
#define PTRS_PER_PGD		2048
#define PTRS_PER_PTE            512
#define pgd_index(addr)         ((addr) >> PGDIR_SHIFT)
#define pte_index(addr)         (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_pfn(pte)            (pte >> PAGE_SHIFT)

#define TASK_SIZE		0xC0000000

#define BIT_YOUNG		1
#define BIT_FILE		2
#define BIT_DIRTY		6
#define BIT_RDONLY		7
#define BIT_XN			9

#define VERBOSE_OPT		"-v"

int main(int argc, char **argv)
{
	int verbose;
	pid_t pid;
	char *end;
	unsigned long va, pte_base, pte_va, pte, index_pgd, index_pte;

	if (argc < 2 || argc > 3) {
		printf("Usage: vm_inspector <-v> <pid>\n");
		return 0;
	}

	if (argc == 2) {
		pid = strtol(argv[1], &end, 10);
	} else {
		if (strcmp(argv[1], VERBOSE_OPT) == 0)
			verbose = 1;

		pid = strtol(argv[2], &end, 10);
	}

	if (*end) {
		printf("error: could not parse pid");
		exit(1);
	}

	void *fake_pgd = mmap(NULL, PTRS_PER_PGD * sizeof(unsigned long),
				PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (fake_pgd == MAP_FAILED) {
		printf("error: create fake_pgd failed\n");
		exit(1);
	}

	void *addr = mmap(NULL, PTRS_PER_PGD * PAGE_SIZE,
				PROT_READ,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (addr == MAP_FAILED) {
		printf("error: create addr failed\n");
		exit(1);
	}

	if (syscall(__NR_expose_page_table, pid,
		(unsigned long) fake_pgd,
		(unsigned long) addr) < 0) {
		printf("error: expose_page_table failed!\n");
		exit(1);
	}

	for (va = 0; va < TASK_SIZE; va += PAGE_SIZE) {
		index_pgd = pgd_index(va);
		pte_base = *((unsigned long *) (fake_pgd +
				(index_pgd * sizeof(unsigned long))));

		if (pte_base) {
			index_pte = pte_index(va);
			pte_va = pte_base + (index_pte * sizeof(unsigned long));
			pte = *((unsigned long *) pte_va);
			if (pte) {
				printf("0x%lx 0x%lx 0x%lx %d %d %d %d %d\n",
					index_pgd,
					va,
					pte_pfn(pte),
					(int) CHECK_BIT(pte, BIT_YOUNG),
					(int) CHECK_BIT(pte, BIT_FILE),
					(int) CHECK_BIT(pte, BIT_DIRTY),
					(int) CHECK_BIT(pte, BIT_RDONLY),
					(int) CHECK_BIT(pte, BIT_XN));
			} else if (verbose) {
				printf("0x%lx 0x%lx 0x%lx %d %d %d %d %d\n",
					index_pgd,
					va,
					(unsigned long) 0, 0, 0, 0, 0, 0);
			}
		}
	}

	if (munmap(fake_pgd, PTRS_PER_PGD * sizeof(unsigned long)) == -1) {
		printf("error: release fake_pgd failed\n");
		exit(1);
	}

	if (munmap(addr, PTRS_PER_PGD * PAGE_SIZE) == -1) {
		printf("error: release addr failed\n");
		exit(1);
	}

	return 0;
}

/*
 *  mm/expose.c
 *
 *  Method to expose a process's page table in userspace
 *
 *  Copyright (C) 2010  Linus Torvalds
 */

#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

SYSCALL_DEFINE3(expose_page_table, pid_t, pid, unsigned long, fake_pgd,
						unsigned long, addr)
{
	struct vm_area_struct *pgd_vma, *pt_vma;
	struct task_struct *p;
	unsigned long va, pa, pfn, zero;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	int res = 0;
	int i, j, k;

	zero = 0;

	if (pid < -1)
		return -EINVAL;

	if (pid == -1) {
		pid = current->pid;
		p = current;
	} else {
		p = find_task_by_vpid(pid);
		if (!p)
			return -EINVAL;
	}

	/* We do not process kernel threads, which have NULL mm */
	if (!p->mm)
		return -EINVAL;

	down_read(&p->mm->mmap_sem);

	pgd_vma = find_vma(current->mm, fake_pgd);
	pt_vma = find_vma(current->mm, addr);

	if (!pgd_vma || !pt_vma) {
		res = -EINVAL;
		goto out;
	}

	if (pgd_vma->vm_end - fake_pgd < PTRS_PER_PGD * sizeof(unsigned long))
		res = -EINVAL;

	if (pt_vma->vm_end - addr < PTRS_PER_PGD * PAGE_SIZE)
		res = -EINVAL;

	if (pgd_vma->vm_flags & VM_EXEC)
		res = -EINVAL;

	if (pt_vma->vm_flags & VM_WRITE || pt_vma->vm_flags & VM_EXEC)
		res = -EINVAL;

	if (res)
		goto out;

	pgd_vma->vm_flags |= VM_RESERVED;
	pt_vma->vm_flags |= VM_RESERVED;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		pgd = p->mm->pgd + i;

		/* Stop if reached end of userspace memory */
		if (i >= pgd_index(TASK_SIZE))
			break;

		if (pgd_none(*pgd) || pgd_bad(*pgd))
			continue;

		pud = pud_offset(pgd, zero);

		for (j = 0; j < PTRS_PER_PUD; j++) {
			if (pud_none(*pud) || pud_bad(*pud))
				continue;

			pmd = pmd_offset(pud, zero);

			for (k = 0; k < PTRS_PER_PMD; k++) {
				if (pmd_none(*pmd) || pmd_bad(*pmd))
					continue;

				pa = pmd_val(*pmd);

				/* Ignore 1mb sections based on last bit */
				if (pa && (pa & (1 << 0))) {
					pfn = pa >> PAGE_SHIFT;
					va = addr;
					remap_pfn_range(pt_vma, va, pfn,
						PAGE_SIZE, PAGE_READONLY);
				} else {
					va = 0;
				}

				/* Put the va in fake_pgd */
				if (copy_to_user((void *)
					(fake_pgd + i * sizeof(va)),
					&va, sizeof(va))) {
					res = -EFAULT;
					goto out;
				}

				addr += PAGE_SIZE;

				pmd++;
			}

			pud++;
		}
	}

out:
	up_read(&p->mm->mmap_sem);
	return res;
}

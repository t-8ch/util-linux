/*
 * Copyright (C) 2023 Thomas Weißschuh <thomas@t-8ch.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stddef.h>
#include <stdbool.h>
#include <getopt.h>

#include <linux/unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/fs.h>
#include <sys/prctl.h>

#include "c.h"
#include "exitcodes.h"
#include "nls.h"

#if __x86_64__
#    define SECCOMP_ARCH_NATIVE AUDIT_ARCH_X86_64
#elif __i386__
#    define SECCOMP_ARCH_NATIVE AUDIT_ARCH_I386
#elif __arm__
#    define SECCOMP_ARCH_NATIVE AUDIT_ARCH_ARM
#elif __aarch64__
#    define SECCOMP_ARCH_NATIVE AUDIT_ARCH_AARCH64
#elif __riscv
#    if __riscv_xlen == 32
#        define SECCOMP_ARCH_NATIVE AUDIT_ARCH_RISCV32
#    elif __riscv_xlen == 64
#        define SECCOMP_ARCH_NATIVE AUDIT_ARCH_RISCV64
#    endif
#elif __s390x__
# 	 define SECCOMP_ARCH_NATIVE AUDIT_ARCH_S390X
#elif __s390__
# 	 define SECCOMP_ARCH_NATIVE AUDIT_ARCH_S390
#elif __PPC64__
#    if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# 	 define SECCOMP_ARCH_NATIVE AUDIT_ARCH_PPC64
#    else
# 	 define SECCOMP_ARCH_NATIVE AUDIT_ARCH_PPC64LE
#    endif
#else
#    error Unknown target architecture
#endif

#define UL_BPF_NOP (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0)

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define syscall_arch (offsetof(struct seccomp_data, arch))
#define syscall_arg(n) (offsetof(struct seccomp_data, args[n]))

struct syscall {
	const char *const name;
	long number;
};

static const struct syscall syscalls[] = {
	/* sorted alphabetically */
#define UL_SYSCALL(name, nr) { name, nr },
#include "syscalls.h"
#undef UL_SYSCALL
};
static_assert(sizeof(syscalls) > 0, "no syscalls found");

static const struct syscall ioctls[] = {
	{ "FITHAW", FITHAW },
};
static_assert(sizeof(ioctls) > 0, "no ioctls found");

static void __attribute__((__noreturn__)) usage(void)
{
	FILE *out = stdout;

	fputs(USAGE_HEADER, out);
	fprintf(out, _(" %s [options] -- <command>\n"), program_invocation_short_name);

	fputs(USAGE_OPTIONS, out);
	fputs(_(" -s, --syscall           syscall to block\n"), out);
	fputs(_(" -l, --list              list known syscalls\n"), out);

	fputs(USAGE_SEPARATOR, out);
	fprintf(out, USAGE_HELP_OPTIONS(25));

	fprintf(out, USAGE_MAN_TAIL("enosys(1)"));

	exit(EXIT_SUCCESS);
}

struct syscall_group {
	const char *const name;
	long *numbers;
};

#define NO_SYSCALL (-1)
#define SYSCALL_GROUP(name, ...) { name, (long[]){ __VA_ARGS__, NO_SYSCALL } }

static const struct syscall_group syscall_groups[] = {
	/* sorted alphabetically */
	SYSCALL_GROUP("new_mount", __NR_fsopen, __NR_move_mount, __NR_open_tree),
};

static const char *syscall_name(long number)
{
	for (size_t i = 0; i < ARRAY_SIZE(syscalls); i++) {
		if (syscalls[i].number == number)
			return syscalls[i].name;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int c;
	size_t i, j;
	bool found;
	static const struct option longopts[] = {
		{ "syscall", required_argument, NULL, 's' },
		{ "ioctl",   required_argument, NULL, 'i' },
		{ "list",    no_argument,       NULL, 'l' },
		{ "version", no_argument,       NULL, 'V' },
		{ "help",    no_argument,       NULL, 'h' },
		{ 0 }
	};

	bool blocked_syscalls[ARRAY_SIZE(syscalls)] = {};
	bool blocked_ioctls[ARRAY_SIZE(ioctls)] = {};

	while ((c = getopt_long (argc, argv, "Vhs:i:l", longopts, NULL)) != -1) {
		switch (c) {
		case 's':
			found = 0;
			if (optarg[0] == '@') {
				for (i = 0; i < ARRAY_SIZE(syscall_groups); i++) {
					if (strcmp(optarg + 1, syscall_groups[i].name) == 0) {
						found = 1;

						for (j = 0; syscall_groups[i].numbers[j] != NO_SYSCALL; j++)
							blocked_syscalls[syscall_groups[i].numbers[j]] = true;
						break;
					}
				}
			} else {
				for (i = 0; i < ARRAY_SIZE(syscalls); i++) {
					if (strcmp(optarg, syscalls[i].name) == 0) {
						found = 1;
						blocked_syscalls[i] = true;
						break;
					}
				}
			}
			if (!found)
				errx(EXIT_FAILURE, _("Unknown syscall '%s'"), optarg);
			break;
		case 'i':
			found = 0;
			for (i = 0; i < ARRAY_SIZE(ioctls); i++) {
				if (strcmp(optarg, ioctls[i].name) == 0) {
					found = 1;
					blocked_ioctls[i] = true;
					break;
				}
			}
			if (!found)
				errx(EXIT_FAILURE, _("Unknown ioctl '%s'"), optarg);
			break;
		case 'l':
			for (i = 0; i < ARRAY_SIZE(syscalls); i++)
				printf("%s\n", syscalls[i].name);
			for (i = 0; i < ARRAY_SIZE(syscall_groups); i++) {
				printf("@%s: ", syscall_groups[i].name);
				for (j = 0; syscall_groups[i].numbers[j] != NO_SYSCALL; j++) {
					printf("%s ", syscall_name(syscall_groups[i].numbers[j]));
				}
				printf("\n");
			}
			return EXIT_SUCCESS;
		case 'V':
			print_version(EXIT_SUCCESS);
		case 'h':
			usage();
		default:
			errtryhelp(EXIT_FAILURE);
		}
	}

	if (optind >= argc)
		errtryhelp(EXIT_FAILURE);

#define N_FILTERS (ARRAY_SIZE(syscalls) * 2 + ARRAY_SIZE(ioctls) * 2 + 8)

	struct sock_filter filter[N_FILTERS];
	static_assert(ARRAY_SIZE(filter) <= BPF_MAXINSNS, "bpf filter too big");

	struct sock_filter *f = filter;

	*f++ = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_arch);
	*f++ = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_ARCH_NATIVE, 1, 0);
	*f++ = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP);
	*f++ = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr);

	for (i = 0; i < ARRAY_SIZE(syscalls); i++) {
		*f++ = (struct sock_filter) BPF_JUMP(
				BPF_JMP | BPF_JEQ | BPF_K,
				syscalls[i].number,
				0, 1);
		*f++ = blocked_syscalls[i]
			? (struct sock_filter) BPF_STMT(
					BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS)
			: UL_BPF_NOP;
	}

	*f++ = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 1, 0);
	*f++ = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

	*f++ = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_arg(1));

	for (i = 0; i < ARRAY_SIZE(ioctls); i++) {
		*f++ = (struct sock_filter) BPF_JUMP(
				BPF_JMP | BPF_JEQ | BPF_K,
				ioctls[i].number,
				0, 1);
		*f++ = blocked_ioctls[i]
			? (struct sock_filter) BPF_STMT(
					BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOTTY)
			: UL_BPF_NOP;
	}

	*f++ = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

	struct sock_fprog prog = {
		.len    = ARRAY_SIZE(filter),
		.filter = filter,
	};

	/* *SET* below will return EINVAL when either the filter is invalid or
	 * seccomp is not supported. To distinguish those cases do a *GET* here
	 */
	if (prctl(PR_GET_SECCOMP) == -1 && errno == EINVAL)
		err(EXIT_NOTSUPP, _("Seccomp non-functional"));

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		err_nosys(EXIT_FAILURE, _("Could not run prctl(PR_SET_NO_NEW_PRIVS)"));

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		err_nosys(EXIT_FAILURE, _("Could not run prctl(PR_SET_SECCOMP)"));

	if (execvp(argv[optind], argv + optind))
		err(EXIT_NOTSUPP, _("Could not exec"));
}

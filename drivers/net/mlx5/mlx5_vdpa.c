/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#include <rte_bus_pci.h>
#include <rte_errno.h>

#include "mlx5_glue.h"
#include "mlx5_defs.h"
#include "mlx5_utils.h"

/** Driver-specific log messages type. */
int mlx5_vdpa_logtype;

/**
 * DPDK callback to register a PCI device.
 *
 * This function spawns vdpa device out of a given PCI device.
 *
 * @param[in] pci_drv
 *   PCI driver structure (mlx5_vpda_driver).
 * @param[in] pci_dev
 *   PCI device information.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
mlx5_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		    struct rte_pci_device *pci_dev __rte_unused)
{
	rte_errno = ENOENT;
	return -rte_errno;
}

/**
 * DPDK callback to remove a PCI device.
 *
 * This function removes all Ethernet devices belong to a given PCI device.
 *
 * @param[in] pci_dev
 *   Pointer to the PCI device.
 *
 * @return
 *   0 on success, the function cannot fail.
 */
static int
mlx5_vdpa_pci_remove(struct rte_pci_device *pci_dev __rte_unused)
{
	return 0;
}

static const struct rte_pci_id mlx5_vdpa_pci_id_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5BFVF)
	},
	{
		.vendor_id = 0
	}
};

static struct rte_pci_driver mlx5_vdpa_driver = {
	.driver = {
		.name = "net_mlx5_vdpa",
	},
	.id_table = mlx5_vdpa_pci_id_map,
	.probe = mlx5_vdpa_pci_probe,
	.remove = mlx5_vdpa_pci_remove,
	.drv_flags = 0,
};

#ifdef RTE_LIBRTE_MLX5_DLOPEN_DEPS

/**
 * Suffix RTE_EAL_PMD_PATH with "-glue".
 *
 * This function performs a sanity check on RTE_EAL_PMD_PATH before
 * suffixing its last component.
 *
 * @param buf[out]
 *   Output buffer, should be large enough otherwise NULL is returned.
 * @param size
 *   Size of @p out.
 *
 * @return
 *   Pointer to @p buf or @p NULL in case suffix cannot be appended.
 */
static char *
mlx5_glue_path(char *buf, size_t size)
{
	static const char *const bad[] = { "/", ".", "..", NULL };
	const char *path = RTE_EAL_PMD_PATH;
	size_t len = strlen(path);
	size_t off;
	int i;

	while (len && path[len - 1] == '/')
		--len;
	for (off = len; off && path[off - 1] != '/'; --off)
		;
	for (i = 0; bad[i]; ++i)
		if (!strncmp(path + off, bad[i], (int)(len - off)))
			goto error;
	i = snprintf(buf, size, "%.*s-glue", (int)len, path);
	if (i == -1 || (size_t)i >= size)
		goto error;
	return buf;
error:
	DRV_LOG(ERR,
		"unable to append \"-glue\" to last component of"
		" RTE_EAL_PMD_PATH (\"" RTE_EAL_PMD_PATH "\"),"
		" please re-configure DPDK");
	return NULL;
}

/**
 * Initialization routine for run-time dependency on rdma-core.
 */
static int
mlx5_glue_init(void)
{
	/*
	 * TODO (shahaf): move it to shared location and make sure glue lib init only once.
	 */
	char glue_path[sizeof(RTE_EAL_PMD_PATH) - 1 + sizeof("-glue")];
	const char *path[] = {
		/*
		 * A basic security check is necessary before trusting
		 * MLX5_GLUE_PATH, which may override RTE_EAL_PMD_PATH.
		 */
		(geteuid() == getuid() && getegid() == getgid() ?
		 getenv("MLX5_GLUE_PATH") : NULL),
		/*
		 * When RTE_EAL_PMD_PATH is set, use its glue-suffixed
		 * variant, otherwise let dlopen() look up libraries on its
		 * own.
		 */
		(*RTE_EAL_PMD_PATH ?
		 mlx5_glue_path(glue_path, sizeof(glue_path)) : ""),
	};
	unsigned int i = 0;
	void *handle = NULL;
	void **sym;
	const char *dlmsg;

	while (!handle && i != RTE_DIM(path)) {
		const char *end;
		size_t len;
		int ret;

		if (!path[i]) {
			++i;
			continue;
		}
		end = strpbrk(path[i], ":;");
		if (!end)
			end = path[i] + strlen(path[i]);
		len = end - path[i];
		ret = 0;
		do {
			char name[ret + 1];

			ret = snprintf(name, sizeof(name), "%.*s%s" MLX5_GLUE,
				       (int)len, path[i],
				       (!len || *(end - 1) == '/') ? "" : "/");
			if (ret == -1)
				break;
			if (sizeof(name) != (size_t)ret + 1)
				continue;
			DRV_LOG(DEBUG, "looking for rdma-core glue as \"%s\"",
				name);
			handle = dlopen(name, RTLD_LAZY);
			break;
		} while (1);
		path[i] = end + 1;
		if (!*end)
			++i;
	}
	if (!handle) {
		rte_errno = EINVAL;
		dlmsg = dlerror();
		if (dlmsg)
			DRV_LOG(WARNING, "cannot load glue library: %s", dlmsg);
		goto glue_error;
	}
	sym = dlsym(handle, "mlx5_glue");
	if (!sym || !*sym) {
		rte_errno = EINVAL;
		dlmsg = dlerror();
		if (dlmsg)
			DRV_LOG(ERR, "cannot resolve glue symbol: %s", dlmsg);
		goto glue_error;
	}
	mlx5_glue = *sym;
	return 0;
glue_error:
	if (handle)
		dlclose(handle);
	DRV_LOG(WARNING,
		"cannot initialize PMD due to missing run-time dependency on"
		" rdma-core libraries (libibverbs, libmlx5)");
	return -rte_errno;
}

#endif
/**
 * Driver initialization routine.
 */
RTE_INIT(rte_mlx5_vdpa_init)
{
	/* Initialize driver log type. */
	mlx5_vdpa_logtype = rte_log_register("pmd.net.mlx5_vdpa");
	if (mlx5_vdpa_logtype >= 0)
		rte_log_set_level(mlx5_vdpa_logtype, RTE_LOG_NOTICE);

	/*
	 * RDMAV_HUGEPAGES_SAFE tells ibv_fork_init() we intend to use
	 * huge pages. Calling ibv_fork_init() during init allows
	 * applications to use fork() safely for purposes other than
	 * using this PMD, which is not supported in forked processes.
	 */
	setenv("RDMAV_HUGEPAGES_SAFE", "1", 1);
#ifdef RTE_LIBRTE_MLX5_DLOPEN_DEPS
	if (mlx5_glue_init())
		return;
	assert(mlx5_glue);
#endif
#ifndef NDEBUG
	/* Glue structure must not contain any NULL pointers. */
	{
		unsigned int i;

		for (i = 0; i != sizeof(*mlx5_glue) / sizeof(void *); ++i)
			assert(((const void *const *)mlx5_glue)[i]);
	}
#endif
	if (strcmp(mlx5_glue->version, MLX5_GLUE_VERSION)) {
		DRV_LOG(ERR,
			"rdma-core glue \"%s\" mismatch: \"%s\" is required",
			mlx5_glue->version, MLX5_GLUE_VERSION);
		return;
	}
	mlx5_glue->fork_init();
	rte_pci_register(&mlx5_vdpa_driver);
}

RTE_PMD_EXPORT_NAME(net_mlx5_vdpa, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(net_mlx5_vdpa, mlx5_vdpa_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mlx5_vdpa, "* ib_uverbs & mlx5_core & mlx5_ib");

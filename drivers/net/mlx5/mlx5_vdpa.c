/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#include <rte_bus_pci.h>
#include <rte_errno.h>
#include <rte_vdpa.h>
#include <rte_malloc.h>
#include <unistd.h>
#include <dlfcn.h>

#include "mlx5_glue.h"
#include "mlx5_defs.h"
#include "mlx5_utils.h"
#include "mlx5.h"
#include "mlx5_prm.h"

/** Driver Static values in the absence of device VIRTIO emulation support */
#define MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED 1

/** Driver-specific log messages type. */
int mlx5_vdpa_logtype;

struct mlx5_vdpa_caps {
	uint32_t dump_mkey;
	uint16_t max_num_virtqs;
	uint64_t virtio_net_features;
};

struct vdpa_priv {
	int id; /* vDPA device id. */
	int vid; /* Vhost-lib virtio_net driver id */
	uint32_t pdn; /* PD number */
	struct mlx5dv_devx_obj *pd_obj; /* PD object handler */
	rte_atomic32_t dev_attached;
	struct ibv_context *ctx; /* Device context. */
	struct rte_vdpa_dev_addr dev_addr;
	struct mlx5_vdpa_caps caps;

};
struct vdpa_priv_list {
	TAILQ_ENTRY(vdpa_priv_list) next;
	struct vdpa_priv *priv;
};

TAILQ_HEAD(vdpa_priv_list_head, priv_list);
static struct vdpa_priv_list_head priv_list =
					TAILQ_HEAD_INITIALIZER(priv_list);
static pthread_mutex_t priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

static int create_pd(struct vdpa_priv *priv)
{
    uint32_t in[MLX5_ST_SZ_DW(alloc_pd_in)] = {0};
    uint32_t out[MLX5_ST_SZ_DW(alloc_pd_out)] = {0};
    struct mlx5dv_devx_obj *pd;

    MLX5_SET(alloc_pd_in, in, opcode, MLX5_CMD_OP_ALLOC_PD);
    pd = mlx5_glue->dv_devx_obj_create(priv->ctx, in, sizeof(in),
                                       out, sizeof(out));
    if (!pd) {
        DRV_LOG(ERR, "PD allocation failure");
        return -1;
    }
    priv->pdn = MLX5_GET(alloc_pd_out, out, pd);
    priv->pd_obj = pd;
    return 0;
}

static struct vdpa_priv_list *
find_priv_resource_by_did(int did)
{
    int found = 0;
    struct vdpa_priv_list *list;

    pthread_mutex_lock(&priv_list_lock);
    TAILQ_FOREACH(list, &priv_list, next) {
        if (did == list->priv->id) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&priv_list_lock);
    if (!found)
        return NULL;
    return list;
}

static int
mlx5_vdpa_get_queue_num(int did, uint32_t *queue_num)
{
    struct vdpa_priv_list *list_elem;

    list_elem = find_priv_resource_by_did(did);
    if (list_elem == NULL) {
        DRV_LOG(ERR, "Invalid device id: %d", did);
        return -1;
    }
    *queue_num = list_elem->priv->caps.max_num_virtqs;
    return 0;
}

static int
mlx5_vdpa_get_vdpa_features(int did, uint64_t *features)
{
	struct vdpa_priv_list *list_elem;

	list_elem = find_priv_resource_by_did(did);
	if (list_elem == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	*features = list_elem->priv->caps.virtio_net_features;
	return 0;
}

static int
mlx5_vdpa_dev_config(int vid)
{
    int did;
    struct vdpa_priv_list *list_elem;
    struct vdpa_priv *priv;

    did = rte_vhost_get_vdpa_device_id(vid);
    list_elem = find_priv_resource_by_did(did);
    if (list_elem == NULL) {
        DRV_LOG(ERR, "Invalid device id: %d", did);
        return -1;
    }
    priv = list_elem->priv;
    priv->vid = vid;
    if (create_pd(priv)) {
        DRV_LOG(ERR, "Error allocating PD");
        return -1;
    }
    rte_atomic32_set(&priv->dev_attached, 1);
    return 0;
}

static int
mlx5_vdpa_dev_close(int vid)
{
    int did;
    struct vdpa_priv_list *list_elem;
    struct vdpa_priv *priv;

    did = rte_vhost_get_vdpa_device_id(vid);
    list_elem = find_priv_resource_by_did(did);
    if (list_elem == NULL) {
        DRV_LOG(ERR, "Invalid device id: %d", did);
        return -1;
    }
    priv = list_elem->priv;
    if (mlx5_glue->dv_devx_obj_destroy(priv->pd_obj)) {
        DRV_LOG(ERR, "Error when DEALLOCATING PD");
        return -1;
    }
    priv->pdn = 0;
    rte_atomic32_set(&priv->dev_attached, 0);
    return 0;
}

static struct rte_vdpa_dev_ops mlx5_vdpa_ops = {
	.get_queue_num = mlx5_vdpa_get_queue_num,
	.get_features = mlx5_vdpa_get_vdpa_features,
	.get_protocol_features = NULL,
	.dev_conf = mlx5_vdpa_dev_config,
	.dev_close = mlx5_vdpa_dev_close,
	.set_vring_state = NULL,
	.set_features = NULL,
	.migration_done = NULL,
	.get_vfio_group_fd = NULL,
	.get_vfio_device_fd = NULL,
	.get_notify_area = NULL,
};

static int
mlx5_vdpa_query_virtio_caps(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(query_hca_cap_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(query_hca_cap_out)] = {0};
	uint32_t in_special[MLX5_ST_SZ_DW(query_special_contexts_in)] = {0};
	uint32_t out_special[MLX5_ST_SZ_DW(query_special_contexts_out)] = {0};
	uint8_t dump_mkey_reported = 0;
	void *virtio_net_cap = NULL;
	void *cap = NULL;

	MLX5_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	MLX5_SET(query_hca_cap_in, in, op_mod,
			(MLX5_HCA_CAP_GENERAL << 1) |
			(MLX5_HCA_CAP_OPMOD_GET_CUR & 0x1));
	if (mlx5_glue->dv_devx_general_cmd(priv->ctx, in, sizeof(in),
                                       out, sizeof(out))) {
	    DRV_LOG(DEBUG, "Failed to Query Current HCA CAP section\n");
	    return -1;
	}
	cap = MLX5_ADDR_OF(query_hca_cap_out, out, capability);
	dump_mkey_reported = MLX5_GET(cmd_hca_cap, cap, dump_fill_mkey);
	if (!dump_mkey_reported) {
	    DRV_LOG(DEBUG, "dump_fill_mkey is not supported\n");
	    return -1;
	}
	/* Query the actual dump key. */
	MLX5_SET(query_special_contexts_in, in_special, opcode,
		 MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS);
	if (mlx5_glue->dv_devx_general_cmd(priv->ctx, in_special, sizeof(in_special),
                                       out_special, sizeof(out_special))) {
	    DRV_LOG(DEBUG, "Failed to Query Special Contexts\n");
		return -1;
	}
	priv->caps.dump_mkey = MLX5_GET(query_special_contexts_out,
					out_special,
					dump_fill_mkey);
	/*
	 * TODO (idos): Once we have FW support, exit if not supported (else path)
	 */
	if (MLX5_GET64(cmd_hca_cap, cap, general_obj_types) &
		MLX5_GENERAL_OBJ_TYPES_CAP_VIRTQ) {
		 DRV_LOG(DEBUG, "Virtio acceleration supported by the device!\n");
		 MLX5_SET(query_hca_cap_in, in, op_mod,
				 (MLX5_HCA_CAP_DEVICE_EMULATION << 1) |
				 (MLX5_HCA_CAP_OPMOD_GET_CUR & 0x1));
		 if (mlx5_glue->dv_devx_general_cmd(priv->ctx, in, sizeof(in),
		                                    out, sizeof(out))) {
			 DRV_LOG(DEBUG, "Failed to Query Emulation CAP section\n");
			 return -1;
		 }
		 virtio_net_cap = MLX5_ADDR_OF(device_emulation, cap, virtnet);
		 priv->caps.max_num_virtqs =
				 MLX5_GET(virtio_net_cap, virtio_net_cap, max_num_of_virtqs);
	} else {
		DRV_LOG(DEBUG, "Virtio acceleration not supported by the device\n");
		priv->caps.max_num_virtqs = MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED;
	}
	priv->caps.max_num_virtqs = MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED;
	priv->caps.virtio_net_features = (1ULL << VHOST_USER_F_PROTOCOL_FEATURES);
	DRV_LOG(DEBUG, "Virtio Caps:");
	DRV_LOG(DEBUG, "	dump_mkey=0x%x ", priv->caps.dump_mkey);
	DRV_LOG(DEBUG, "	max_num_virtqs=0x%x ", priv->caps.max_num_virtqs);
	DRV_LOG(DEBUG, "	features_bits=0x%" PRIx64, priv->caps.virtio_net_features);
	return 0;
}

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
	struct ibv_device **ibv_list;
	struct ibv_device *ibv_match = NULL;
	struct mlx5dv_context_attr devx_attr = {
		.flags = MLX5DV_CONTEXT_FLAGS_DEVX,
		.comp_mask = 0,
	};
	struct vdpa_priv *priv = NULL;
	struct vdpa_priv_list *priv_list_elem = NULL;
	struct ibv_context *ctx;
	int ret;

	assert(pci_drv == &mlx5_vdpa_driver);
	errno = 0;
	ibv_list = mlx5_glue->get_device_list(&ret);
	if (!ibv_list) {
		rte_errno = errno ? errno : ENOSYS;
		DRV_LOG(ERR, "cannot list devices, is ib_uverbs loaded?");
		return -rte_errno;
	}


	while (ret-- > 0) {
		struct rte_pci_addr pci_addr;

		DRV_LOG(DEBUG, "checking device \"%s\"", ibv_list[ret]->name);
		if (mlx5_ibv_device_to_pci_addr(ibv_list[ret], &pci_addr))
			continue;
		if (pci_dev->addr.domain != pci_addr.domain ||
		    pci_dev->addr.bus != pci_addr.bus ||
		    pci_dev->addr.devid != pci_addr.devid ||
		    pci_dev->addr.function != pci_addr.function)
			continue;
		DRV_LOG(INFO, "PCI information matches for device \"%s\"",
			ibv_list[ret]->name);
		ibv_match = ibv_list[ret];
		break;
	}
	if (!ibv_match) {
		DRV_LOG(DEBUG, "No matching IB device for PCI slot "
			"%" SCNx32 ":%" SCNx8 ":%" SCNx8 ".%" SCNx8 "\n",
			pci_dev->addr.domain, pci_dev->addr.bus,
			pci_dev->addr.devid, pci_dev->addr.function);
		rte_errno = ENOENT;
		goto error;
	}
	ctx = mlx5_glue->dv_open_device(ibv_match, &devx_attr);
	if (!ctx) {
		DRV_LOG(DEBUG, "Failed to open IB device \"%s\"", ibv_match->name);
		rte_errno = errno ? errno : ENODEV;
		goto error;
	}
	priv = rte_zmalloc("vDPA device private", sizeof(*priv),
			   RTE_CACHE_LINE_SIZE);
	priv_list_elem = rte_zmalloc("vDPA device priv list elem",
				     sizeof(*priv_list_elem),
				     RTE_CACHE_LINE_SIZE);
	if (!priv || !priv_list_elem) {
		DRV_LOG(DEBUG, "Unable to allocate memory for private structure");
		rte_errno = rte_errno ? rte_errno : ENOMEM;
		goto error;
	}
	priv->ctx = ctx;
	priv->dev_addr.pci_addr = pci_dev->addr;
	priv->dev_addr.type = PCI_ADDR;
	if (mlx5_vdpa_query_virtio_caps(priv)) {
		DRV_LOG(DEBUG, "Unable to query Virtio caps");
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}
	priv_list_elem->priv = priv;
	priv->id = rte_vdpa_register_device(&priv->dev_addr,
					     &mlx5_vdpa_ops);
	if (priv->id < 0) {
		DRV_LOG(DEBUG, "Unable to regsiter vDPA device");
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}
	pthread_mutex_lock(&priv_list_lock);
	TAILQ_INSERT_TAIL(&priv_list, priv_list_elem, next);
	pthread_mutex_unlock(&priv_list_lock);
	return 0;

error:
	if (priv)
		rte_free(priv);
	if (priv_list_elem)
		rte_free(priv_list_elem);
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
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5BF)
	},
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

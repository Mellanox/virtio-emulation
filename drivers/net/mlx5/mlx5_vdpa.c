/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/epoll.h>

#include <unistd.h>
#include <dlfcn.h>
#include <rte_bus_pci.h>
#include <rte_errno.h>
#include <rte_vdpa.h>
#include <rte_malloc.h>
#include <rte_common.h>

#include "mlx5_glue.h"
#include "mlx5_defs.h"
#include "mlx5_utils.h"
#include "mlx5.h"
#include "mlx5_prm.h"

#ifndef NOMINMAX
#ifndef max
#define max(a, b)            (((a) > (b)) ? (a) : (b))
#endif
#endif  /* NOMINMAX */

#define MKEY_VARIANT_PART 0x50

/** Driver Static values in the absence of device VIRTIO emulation support */
#define MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED 1
#define SPECIAL_CQ_FOR_VDPA               0

#define MLX5_VDPA_FEATURES ((1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
			    (1ULL << VIRTIO_F_VERSION_1))

#define MLX5_VDPA_PROTOCOL_FEATURES \
			    ((1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ) | \
			     (1ULL << VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD) | \
			     (1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER))

/** Driver-specific log messages type. */
int mlx5_vdpa_logtype;

struct mlx5_vdpa_caps {
	uint32_t dump_mkey;
	uint16_t max_num_virtqs;
	uint64_t virtio_net_features;
	uint64_t virtio_protocol_features;
};

struct virtq_info {
	uint32_t               rqn;
	struct mlx5dv_devx_obj *rq_obj;
};

struct mlx5_vdpa_relay_thread {
	int       epfd; /* Epoll fd for realy thread. */
	pthread_t tid; /* Notify thread id. */
	void      *notify_base; /* Notify base address. */
};

struct mlx5_devx_mkey {
	void		*obj;
	uint32_t	key;
};

struct mlx5_devx_mkey_attr {
	uint64_t        addr;
	uint64_t        size;
	uint32_t        pas_id;
	uint32_t        pd;
	uint32_t        log_entity_size;
	uint32_t        translations_octword_size;
};

struct mlx5_klm {
	uint32_t byte_count;
	uint32_t mkey;
	uint64_t address;
};

struct mlx5_vdpa_query_mr {
	void			*addr;
	uint64_t		length;
	struct mlx5dv_devx_umem *umem;
	struct mlx5_devx_mkey   *mkey;
	int			is_indirect;
};

struct mlx5_vdpa_query_mr_list {
	SLIST_ENTRY(mlx5_vdpa_query_mr_list) next;
	struct mlx5_vdpa_query_mr *vdpa_query_mr;
};

struct vdpa_priv {
	int                           id; /* vDPA device id. */
	int                           vid; /* virtio_net driver id */
	uint32_t                      pdn; /* PD number */
	uint16_t                      nr_vring;
	struct mlx5dv_devx_obj        *pd_obj; /* PD object handler */
	rte_atomic32_t                dev_attached;
	struct ibv_context            *ctx; /* Device context. */
	struct rte_vdpa_dev_addr      dev_addr;
	struct mlx5_vdpa_caps         caps;
	struct mlx5_vdpa_relay_thread relay;
	struct virtq_info virtq[MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED * 2];
	SLIST_HEAD(mr_list, mlx5_vdpa_query_mr_list) mr_list;
};

struct vdpa_priv_list {
	TAILQ_ENTRY(vdpa_priv_list) next;
	struct vdpa_priv           *priv;
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

static int
create_rq(struct vdpa_priv *priv, uint16_t qsize, uint16_t idx)
{
	uint32_t in[MLX5_ST_SZ_DW(create_rq_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_rq_out)] = {0};
	struct mlx5dv_devx_obj *rq_obj = NULL;
	void *rqc = NULL;
	void *wq = NULL;

	MLX5_SET(create_rq_in, in, opcode, MLX5_CMD_OP_CREATE_RQ);
	rqc = MLX5_ADDR_OF(create_rq_in, in, ctx);
	MLX5_SET(rqc, rqc, cqn, SPECIAL_CQ_FOR_VDPA);
	wq = MLX5_ADDR_OF(rqc, rqc, wq);
	/* TODO(idos): Check log_wq_size according to device CAP */
	MLX5_SET(wq, wq, log_wq_sz, qsize);
	MLX5_SET(wq, wq, pd, priv->pdn);
	rq_obj = mlx5_glue->dv_devx_obj_create(priv->ctx, in, sizeof(in),
					       out, sizeof(out));
	if (!rq_obj) {
		DRV_LOG(DEBUG, "Failed to CREATE_RQ through Devx\n");
		return -1;
	}
	priv->virtq[idx].rqn = MLX5_GET(create_rq_out, out, rqn);
	priv->virtq[idx].rq_obj = rq_obj;

	return 0;
}

/*
 * According to VIRTIO_NET Spec the virtqueues index identity its type by:
 * 0 receiveq1
 * 1 transmitq1
 * ...
 * 2(N-1) receiveqN
 * 2(N-1)+1 transmitqN
 * 2N controlq
 */
static bool is_virtq_recvq(int virtq_index, int nr_vring)
{
	if (virtq_index % 2 == 0 && virtq_index != nr_vring - 1)
		return true;
	return false;
}

static int mlx5_vdpa_setup_virtqs(struct vdpa_priv *priv)
{
	int i, nr_vring;
	struct rte_vhost_vring vq;

	nr_vring = rte_vhost_get_vring_num(priv->vid);
	/* TODO(idos): Remove when have MQ support */
	assert(nr_vring == 2);
	for (i = 0; i < nr_vring; i++) {
		rte_vhost_get_vhost_vring(priv->vid, i, &vq);
		if (is_virtq_recvq(i, nr_vring)) {
			if (create_rq(priv, vq.size, i)) {
				DRV_LOG(ERR,
					"Create RQ failed for Virtqueue %d",
					i);
				/* TODO(idos): Remove this when FW supports */
				DRV_LOG(INFO,
					"Contiuing without RQ of Virtqueue %d",
					i);
			}
		}
	}
	priv->nr_vring = i;
	return 0;
}

static int mlx5_vdpa_release_virtqs(struct vdpa_priv *priv)
{
	struct mlx5dv_devx_obj *rq;
	int i;

	for (i = 0; i < priv->nr_vring; i++) {
		if (is_virtq_recvq(i, priv->nr_vring)) {
			rq = priv->virtq[i].rq_obj;
			if (!rq)
				continue;
			if (mlx5_glue->dv_devx_obj_destroy(rq)) {
				DRV_LOG(ERR, "Error DESTROY)RQ VirtQ %d", i);
				return -1;
			}
			priv->virtq[i].rq_obj = NULL;
			priv->virtq[i].rqn = 0;
		}
	}
	return 0;
}

static
struct mlx5_devx_mkey *mlx5_vdpa_create_mkey(struct ibv_context *ctx,
					struct mlx5_devx_mkey_attr *mkey_attr)
{
	uint32_t in[MLX5_ST_SZ_DW(create_mkey_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_mkey_out)] = {0};
	uint32_t status;
	void *mkc;
	struct mlx5_devx_mkey *mkey = NULL;
	int translations_oct_size = ((((mkey_attr->size + 4095) / 4096) + 1) / 2);

	mkey = rte_zmalloc("mkey", sizeof(*mkey), RTE_CACHE_LINE_SIZE);
	MLX5_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, lw, 0x1);
	MLX5_SET(mkc, mkc, lr, 0x1);
	MLX5_SET(mkc, mkc, rw, 0x1);
	MLX5_SET(mkc, mkc, rr, 0x1);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, length64, 0x0);
	MLX5_SET(mkc, mkc, pd, mkey_attr->pd);
	MLX5_SET(mkc, mkc, mkey_7_0, MKEY_VARIANT_PART);//FIXME: should be dynamic
	MLX5_SET(mkc, mkc, translations_octword_size,translations_oct_size);
	MLX5_SET(create_mkey_in, in, translations_octword_actual_size,
		translations_oct_size);
	MLX5_SET(create_mkey_in, in, pg_access, 1);
	MLX5_SET64(mkc, mkc, start_addr, mkey_attr->addr);
	MLX5_SET64(mkc, mkc, len, mkey_attr->size);
	MLX5_SET(mkc, mkc, log_page_size, 12);
	MLX5_SET(create_mkey_in, in, mkey_umem_id, mkey_attr->pas_id);

	mkey->obj = mlx5_glue->dv_devx_obj_create(ctx, in, sizeof(in), out,
					   sizeof(out));
	if (!mkey->obj) {
		DRV_LOG(ERR, "Can't create mkey error %s", strerror(errno));
		goto error;
	}
	status = MLX5_GET(create_mkey_out, out, status);
	mkey->key = MLX5_GET(create_mkey_out, out, mkey_index);
	mkey->key = (mkey->key << 8) | MKEY_VARIANT_PART;
	DRV_LOG(DEBUG, "create mkey status %d mkey value %d",
		status, (mkey->key));
	if (status)
		goto error;
	return mkey;
error:
	if (mkey)
		rte_free(mkey);
	return NULL;
}

static
struct mlx5_devx_mkey *mlx5_create_indirect_mkey(struct ibv_context *ctx,
					struct mlx5_devx_mkey_attr *mkey_attr,
					struct mlx5_klm *klm_array, int num_klm)
{
	int translations_oct_size = (((num_klm / 4) + (num_klm % 4)) * 4);
	uint32_t in_size = MLX5_ST_SZ_DB(create_mkey_in) +
				translations_oct_size * MLX5_ST_SZ_DB(klm);
	uint32_t *in = rte_zmalloc("in", in_size, 64);
	uint32_t out[MLX5_ST_SZ_DW(create_mkey_out)] = {0};
	uint32_t status;
	void *mkc;
	struct mlx5_devx_mkey *mkey = NULL;
	uint8_t *klm = (uint8_t *)MLX5_ADDR_OF(create_mkey_in, in, klm_pas_mtt);

	mkey = rte_zmalloc("mkey", sizeof(*mkey), RTE_CACHE_LINE_SIZE);
	MLX5_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, lw, 0x1);
	MLX5_SET(mkc, mkc, lr, 0x1);
	MLX5_SET(mkc, mkc, rw, 0x1);
	MLX5_SET(mkc, mkc, rr, 0x1);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_KSM);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, length64, 0x0);
	MLX5_SET(mkc, mkc, pd, mkey_attr->pd);
	MLX5_SET(mkc, mkc, mkey_7_0, MKEY_VARIANT_PART);//FIXME: should be dynamic
	MLX5_SET(mkc, mkc, translations_octword_size, translations_oct_size);
	MLX5_SET(create_mkey_in, in,
		translations_octword_actual_size, translations_oct_size);
	MLX5_SET(create_mkey_in, in, pg_access, 0);
	MLX5_SET64(mkc, mkc, start_addr, mkey_attr->addr);
	MLX5_SET64(mkc, mkc, len, mkey_attr->size);
	MLX5_SET(mkc, mkc, log_page_size, max(mkey_attr->log_entity_size, 12));
	for (int i = 0; i < num_klm; i++) {
		MLX5_SET(klm, klm, mkey, klm_array[i].mkey);
		MLX5_SET64(klm, klm, address, klm_array[i].address);
		klm += MLX5_ST_SZ_DB(klm);
	}
	for (int i = num_klm; i < translations_oct_size; i++) {
		MLX5_SET(klm, klm, mkey, 0x0);
		MLX5_SET64(klm, klm, address, 0x0);
		klm += MLX5_ST_SZ_DB(klm);
	}
	mkey->obj = mlx5_glue->dv_devx_obj_create(ctx, in, in_size, out,
						  sizeof(out));
	if (!mkey->obj) {
		DRV_LOG(ERR, "Can't create mkey error %s", strerror(errno));
		goto error;
	}
	status = MLX5_GET(create_mkey_out, out, status);
	mkey->key = MLX5_GET(create_mkey_out, out, mkey_index);
	mkey->key = (mkey->key << 8) | MKEY_VARIANT_PART;
	if (status)
		return NULL;

	return mkey;
error:
	if (mkey)
		rte_free(mkey);
	return NULL;
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

#define MLX5_IB_MMAP_CMD_SHIFT 8
#define MLX5_IB_MMAP_INDEX_MASK ((1 << MLX5_IB_MMAP_CMD_SHIFT) - 1)
#define MLX5_IB_CMD_SIZE 8
#define MLX5_IB_MMAP_VIRTIO_NOTIFY 9
static inline void
mlx5_vdpa_set_command(int command, uint16_t *offset)
{
	*offset |= (command << MLX5_IB_MMAP_CMD_SHIFT);
}

static inline void
mlx5_vdpa_set_ext_index(int index, uint16_t *offset)
{
	uint16_t shift = MLX5_IB_MMAP_CMD_SHIFT + MLX5_IB_CMD_SIZE;

	*offset |= (((index >> MLX5_IB_MMAP_CMD_SHIFT) << shift) |
		    (index & MLX5_IB_MMAP_INDEX_MASK));
}

/*
 * Currently there is a single offset for all of the queues doorbells.
 */
static inline uint16_t
mlx5_vdpa_get_notify_offset(int qid __rte_unused)
{
	uint16_t offset = 0;

	mlx5_vdpa_set_command(MLX5_IB_MMAP_VIRTIO_NOTIFY, &offset);
	mlx5_vdpa_set_ext_index(0, &offset);
	return offset;
}

static int
mlx5_vdpa_report_notify_area(int vid __rte_unused, int qid, uint64_t *offset,
			     uint64_t *size)
{
	long page_size = sysconf(_SC_PAGESIZE);

	*offset = mlx5_vdpa_get_notify_offset(qid);
	*offset = *offset * page_size;
	/*
	 * For now size can be only page size. smaller size does not fit
	 * naturally to the way KVM subscribe translations into the EPT.
	 *
	 * This much fit BlueField1 solution. need to evaluate if we can
	 * bypass this issue in SW to match ConnectX-6 implementation.
	 */
	*size = page_size;
	DRV_LOG(DEBUG, "Notify offset is 0x%" PRIx64 " size is %" PRId64,
		*offset, *size);
	return 0;
}

static void
mlx5_vdpa_notify_queue(struct vdpa_priv *priv, int qid __rte_unused)
{
	/*
	 * Write must be 4B in length in order to pass the device PCI.
	 * need to further investigate the root cause.
	 */
	rte_write32(qid, priv->relay.notify_base);
}

static void *
mlx5_vdpa_notify_relay(void *arg)
{
	int i, kickfd, epfd, nfds = 0;
	uint32_t qid, q_num;
	struct epoll_event events[MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED * 2];
	struct epoll_event ev;
	uint64_t buf;
	int nbytes;
	struct rte_vhost_vring vring;
	struct vdpa_priv *priv = (struct vdpa_priv *)arg;

	q_num = rte_vhost_get_vring_num(priv->id);
	epfd = epoll_create(MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED * 2);
	if (epfd < 0) {
		DRV_LOG(ERR, "failed to create epoll instance.");
		return NULL;
	}
	priv->relay.epfd = epfd;
	for (qid = 0; qid < q_num; qid++) {
		ev.events = EPOLLIN | EPOLLPRI;
		rte_vhost_get_vhost_vring(priv->id, qid, &vring);
		ev.data.u64 = qid | (uint64_t)vring.kickfd << 32;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, vring.kickfd, &ev) < 0) {
			DRV_LOG(ERR, "epoll add error: %s", strerror(errno));
			return NULL;
		}
	}
	for (;;) {
		nfds = epoll_wait(epfd, events, q_num, -1);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			DRV_LOG(ERR, "epoll_wait return fail\n");
			return NULL;
		}
		for (i = 0; i < nfds; i++) {
			qid = events[i].data.u32;
			kickfd = (uint32_t)(events[i].data.u64 >> 32);
			do {
				nbytes = read(kickfd, &buf, 8);
				if (nbytes < 0) {
					if (errno == EINTR ||
					    errno == EWOULDBLOCK ||
					    errno == EAGAIN)
						continue;
					DRV_LOG(INFO, "Error reading "
						"kickfd: %s",
						strerror(errno));
				}
				break;
			} while (1);
			mlx5_vdpa_notify_queue(priv, qid);
		}
	}
	return NULL;
}

static int
mlx5_vdpa_setup_notify_relay(struct vdpa_priv *priv)
{
	uint64_t offset, size;
	void *addr;
	long page_size = sysconf(_SC_PAGESIZE);
	int ret;

	/* set the base notify addr */
	if (mlx5_vdpa_report_notify_area(priv->id, 0, &offset, &size) < 0)
		return -1;
	/* Always map the entire page. */
	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		    priv->ctx->cmd_fd, offset);
	if (addr == MAP_FAILED) {
		DRV_LOG(ERR, "Mapping doorbell page failed. device: %d",
			priv->id);
		return -1;
	}
	priv->relay.notify_base = addr;
	/* TODO: enforce the thread affinity. */
	ret = pthread_create(&priv->relay.tid, NULL, mlx5_vdpa_notify_relay,
			     (void *)priv);
	if (ret) {
		DRV_LOG(ERR, "failed to create notify relay pthread.");
		return -1;
	}
	return 0;
}
static int
mlx5_vdpa_dma_map(struct vdpa_priv *priv)
{
	uint32_t i;
	int ret;
	struct rte_vhost_memory *mem = NULL;
	struct mlx5_devx_mkey_attr mkey_attr;
	static int klm_index;
	struct mlx5_vdpa_query_mr *entry = NULL;
	struct mlx5_vdpa_query_mr_list *list_elem = NULL;
	struct rte_vhost_mem_region *reg = NULL;
	/*TODO(liel): Working with KLM size of 1GB, change to GCD on empty_mr and region sizes*/
	uint64_t klm_size = 1073741824;
	uint64_t min_size = klm_size;
	uint64_t mem_size;

	ret = rte_vhost_get_mem_table(priv->id, &mem);
	if (ret < 0) {
		DRV_LOG(ERR, "failed to get VM memory layout.");
		return -1;
	}
	for (i = 0; i < (mem->nregions); i++) {
		if (min_size > mem->regions[i].size) {
			DRV_LOG(ERR, "Min region size is smaller than KLM size.");
			return -1;
		}
	}
	klm_index = 0;
	mem_size = (mem->regions[(mem->nregions - 1)].guest_phys_addr) +
				(mem->regions[(mem->nregions - 1)].size) -
				(mem->regions[0].guest_phys_addr);
	struct mlx5_klm klm_array[mem_size / klm_size];
	for (i = 0; i < mem->nregions; i++) {
		reg = &mem->regions[i];
		DRV_LOG(INFO, "region %u: HVA 0x%" PRIx64 ", "
			"GPA 0x%" PRIx64 ", size 0x%" PRIx64 ".", i,
			reg->host_user_addr, reg->guest_phys_addr, reg->size);
		list_elem = rte_malloc(__func__, sizeof(*list_elem),
				RTE_CACHE_LINE_SIZE);
		entry =
		    rte_malloc(__func__, sizeof(*entry), RTE_CACHE_LINE_SIZE);
		if (!entry || !list_elem) {
			DRV_LOG(ERR, "Unable to allocate memory");
			goto error;
		}
		entry->umem = mlx5_glue->dv_devx_umem_reg(priv->ctx,
					(void *)reg->host_user_addr, reg->size,
					 IBV_ACCESS_LOCAL_WRITE);
		if (!entry->umem) {
			DRV_LOG(ERR, "Failed to register Umem using Devx.");
			goto error;
		}
		mkey_attr.addr = (uintptr_t)(reg->guest_phys_addr);
		mkey_attr.size = reg->size;
		mkey_attr.pas_id = entry->umem->umem_id;
		mkey_attr.pd = priv->pdn;
		entry->mkey = mlx5_vdpa_create_mkey(priv->ctx, &mkey_attr);
		if (!entry->mkey) {
			DRV_LOG(ERR, "Unable to create Mkey");
			goto error;
		}
		entry->addr = (void *)(reg->host_user_addr);
		entry->length = reg->size;
		entry->is_indirect = 0;
		if (i > 0) {
			uint64_t empty_region = reg->guest_phys_addr -
					(mem->regions[i - 1].guest_phys_addr +
					 mem->regions[i - 1].size);
			if (empty_region > 0) {
				uint64_t start_addr =
					mem->regions[i - 1].guest_phys_addr +
					mem->regions[i - 1].size;
				for (uint64_t k = 0;
				     k < empty_region; k += klm_size) {
					klm_array[klm_index].mkey =
						priv->caps.dump_mkey;
					klm_array[klm_index].address =
						start_addr + k;
					klm_index++;
				}
			}
		}
		for (uint64_t k = 0; k < reg->size; k += klm_size) {
			klm_array[klm_index].byte_count = 0;
			klm_array[klm_index].mkey = (uint64_t)entry->mkey;
			klm_array[klm_index].address = reg->guest_phys_addr + k;
			klm_index++;
		}
		list_elem->vdpa_query_mr = entry;
		SLIST_INSERT_HEAD(&priv->mr_list, list_elem, next);
	}
	mkey_attr.addr = (uintptr_t)(mem->regions[0].guest_phys_addr);
	mkey_attr.size = mem_size;
	mkey_attr.pd = priv->pdn;
	mkey_attr.pas_id = 0;
	mkey_attr.log_entity_size = rte_log2_u32(klm_size);
	list_elem =
		rte_malloc(__func__, sizeof(*list_elem), RTE_CACHE_LINE_SIZE);
	entry = rte_malloc(__func__, sizeof(*entry), 0);
	if (!entry || !list_elem) {
		DRV_LOG(ERR, "Unable to allocate memory");
		goto error;
	}
	entry->mkey = mlx5_create_indirect_mkey(priv->ctx,
				&mkey_attr, klm_array, klm_index);
	if (!entry->mkey) {
		DRV_LOG(ERR, "Unable to create indirect Mkey");
		goto error;
	}
	entry->is_indirect = 1;
	list_elem->vdpa_query_mr = entry;
	SLIST_INSERT_HEAD(&priv->mr_list, list_elem, next);
	return 0;
error:
	if (list_elem)
		free(list_elem);
	if (entry)
		free(entry);
	return -1;
}

static int
mlx5_vdpa_release_mr(struct vdpa_priv *priv)
{
	struct mlx5_vdpa_query_mr_list *entry;
	struct mlx5_vdpa_query_mr_list *next;

	entry = SLIST_FIRST(&priv->mr_list);
	while (entry) {
		next = SLIST_NEXT(entry, next);
		if (mlx5_glue->
			dv_devx_obj_destroy(entry->vdpa_query_mr->mkey->obj)) {
			DRV_LOG(ERR, "Error when destoying Mkey objecy");
			return -1;
		}
		rte_free(entry->vdpa_query_mr->mkey);
		if (!entry->vdpa_query_mr->is_indirect) {
			if (mlx5_glue->
				dv_devx_umem_dereg(entry->vdpa_query_mr->umem)) {
				DRV_LOG(ERR, "Error when desregistering Umem");
				return -1;
			}
		}
		rte_free(entry->vdpa_query_mr);
		rte_free(entry);
		entry = next;
	};
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
	if (mlx5_vdpa_dma_map(priv)) {
		DRV_LOG(ERR, "Error DMA mapping VM memory");
		return -1;
	}
	if (mlx5_vdpa_setup_virtqs(priv)) {
		DRV_LOG(ERR, "Error setting up Virtqueues");
		return -1;
	}
	mlx5_vdpa_setup_notify_relay(priv);
	rte_atomic32_set(&priv->dev_attached, 1);
	return 0;
}

static int
mlx5_vdpa_unset_notify_relay(struct vdpa_priv *priv)
{
	void *status;
	long page_size = sysconf(_SC_PAGESIZE);

	if (priv->relay.tid) {
		pthread_cancel(priv->relay.tid);
		pthread_join(priv->relay.tid, &status);
	}
	priv->relay.tid	= 0;
	if (priv->relay.epfd >= 0)
		close(priv->relay.epfd);
	priv->relay.epfd = -1;
	munmap(priv->relay.notify_base, page_size);
	priv->relay.notify_base = NULL;
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
	mlx5_vdpa_unset_notify_relay(priv);
	if (mlx5_vdpa_release_virtqs(priv)) {
		DRV_LOG(ERR, "Error in releasing Virtqueue resources");
		return -1;
	}
	if (mlx5_vdpa_release_mr(priv)) {
		DRV_LOG(ERR, "Error in unmapping MRs");
		return -1;
	}
	if (mlx5_glue->dv_devx_obj_destroy(priv->pd_obj)) {
		DRV_LOG(ERR, "Error when DEALLOCATING PD");
		return -1;
	}
	rte_atomic32_set(&priv->dev_attached, 0);
	return 0;
}

static int
mlx5_vdpa_get_protocol_features(int did, uint64_t *features)
{
	struct vdpa_priv_list *list_elem;

	list_elem = find_priv_resource_by_did(did);
	if (list_elem == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	*features = list_elem->priv->caps.virtio_protocol_features;
	return 0;
}

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
	if (mlx5_glue->dv_devx_general_cmd(priv->ctx, in_special,
					   sizeof(in_special), out_special,
					   sizeof(out_special))) {
		DRV_LOG(DEBUG, "Failed to Query Special Contexts\n");
		return -1;
	}
	priv->caps.dump_mkey = MLX5_GET(query_special_contexts_out,
					out_special,
					dump_fill_mkey);
	/*
	 * TODO (idos): Once we have FW support, exit if not supported
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
		priv->caps.max_num_virtqs = MLX5_GET(virtio_net_cap,
						     virtio_net_cap,
						     max_num_of_virtqs);
	} else {
		DRV_LOG(DEBUG, "Virtio acceleration not supported by the device\n");
		priv->caps.max_num_virtqs = MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED;
	}
	priv->caps.virtio_net_features = MLX5_VDPA_FEATURES;
	priv->caps.virtio_protocol_features = MLX5_VDPA_PROTOCOL_FEATURES;
	DRV_LOG(DEBUG, "Virtio Caps:");
	DRV_LOG(DEBUG, "	dump_mkey=0x%x ", priv->caps.dump_mkey);
	DRV_LOG(DEBUG, "	max_num_virtqs=0x%x ",
			priv->caps.max_num_virtqs);
	DRV_LOG(DEBUG, "	features_bits=0x%" PRIx64,
			priv->caps.virtio_net_features);
	return 0;
}

static int
mlx5_vdpa_get_device_fd(int vid)
{
	int dev_id;
	struct vdpa_priv_list *list;

	dev_id = rte_vhost_get_vdpa_device_id(vid);
	if (dev_id < 0)
		goto error;
	list = find_priv_resource_by_did(dev_id);
	if (!list)
		goto error;
	return list->priv->ctx->cmd_fd;
error:
	DRV_LOG(DEBUG, "Invliad vDPA device id %d", vid);
	return -1;
}

static struct rte_vdpa_dev_ops mlx5_vdpa_ops = {
	.get_queue_num = mlx5_vdpa_get_queue_num,
	.get_features = mlx5_vdpa_get_vdpa_features,
	.get_protocol_features = mlx5_vdpa_get_protocol_features,
	.dev_conf = mlx5_vdpa_dev_config,
	.dev_close = mlx5_vdpa_dev_close,
	.set_vring_state = NULL,
	.set_features = NULL,
	.migration_done = NULL,
	.get_vfio_group_fd = NULL,
	.get_vfio_device_fd = mlx5_vdpa_get_device_fd,
	.get_notify_area = mlx5_vdpa_report_notify_area,
};

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
		DRV_LOG(DEBUG, "Failed to open IB device \"%s\"",
			ibv_match->name);
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
		DRV_LOG(DEBUG, "Unable to register vDPA device");
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
	 * TODO (shahaf): move it to shared location and make sure glue
	 * lib init only once.
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

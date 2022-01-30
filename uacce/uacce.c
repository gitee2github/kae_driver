// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2018 HiSilicon Limited. */
#include <linux/compat.h>
#include <linux/dma-mapping.h>
#include <linux/file.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include "../include_uapi_linux/uacce.h"
#include "../include_linux/uacce.h"

static struct class *uacce_class;
static dev_t uacce_devt;
static DEFINE_MUTEX(uacce_mutex);
static DEFINE_XARRAY_ALLOC(uacce_xa);
static const struct file_operations uacce_fops;
static struct uacce_qfile_region noiommu_ss_default_qfr = {
	.type	=	UACCE_QFRT_SS,
};

static int cdev_get(struct device *dev, void *data)
{
	struct uacce_device *uacce;
	struct device **t_dev = data;

	uacce = container_of(dev, struct uacce_device, dev);
	if (uacce->parent == *t_dev) {
		*t_dev = dev;
		return 1;
	}

	return 0;
}

/**
 * dev_to_uacce - Get structure uacce device from its parent device
 * @dev the device
 */
struct uacce_device *dev_to_uacce(struct device *dev)
{
	struct device **tdev = &dev;
	int ret;

	ret = class_for_each_device(uacce_class, NULL, tdev, cdev_get);
	if (ret) {
		dev = *tdev;
		return container_of(dev, struct uacce_device, dev);
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(dev_to_uacce);

/**
 * uacce_hw_err_isolate - Try to isolate the uacce device with its VFs
 * according to user's configuration of isolation strategy. Warning: this
 * API should be called while there is no user on the device, or the users
 * on this device are suspended by slot resetting preparation of PCI AER.
 * @uacce the uacce device
 */
int uacce_hw_err_isolate(struct uacce_device *uacce)
{
	struct uacce_hw_err *err, *tmp, *hw_err;
	struct uacce_err_isolate *isolate;
	u32 count = 0;

	if (!uacce)
		return -EINVAL;
	isolate = uacce->isolate;

#define SECONDS_PER_HOUR	3600

	/* all the hw errs are processed by PF driver */
	if (uacce->is_vf || atomic_read(&isolate->is_isolate) ||
		!isolate->hw_err_isolate_hz)
		return 0;

	hw_err = kzalloc(sizeof(*hw_err), GFP_ATOMIC);
	if (!hw_err)
		return -ENOMEM;
	hw_err->tick_stamp = jiffies;
	list_for_each_entry_safe(err, tmp, &isolate->hw_errs, list) {
		if ((hw_err->tick_stamp - err->tick_stamp) / HZ >
		    SECONDS_PER_HOUR) {
			list_del(&err->list);
			kfree(err);
		} else {
			count++;
		}
	}
	list_add(&hw_err->list, &isolate->hw_errs);

	if (count >= isolate->hw_err_isolate_hz)
		atomic_set(&isolate->is_isolate, 1);

	return 0;
}
EXPORT_SYMBOL_GPL(uacce_hw_err_isolate);

static void uacce_hw_err_destroy(struct uacce_device *uacce)
{
	struct uacce_hw_err *err, *tmp;

	list_for_each_entry_safe(err, tmp, &uacce->isolate_data.hw_errs, list) {
		list_del(&err->list);
		kfree(err);
	}
}

static int uacce_start_queue(struct uacce_queue *q)
{
	int ret = 0;

	mutex_lock(&uacce_mutex);

	if(q->state != UACCE_Q_INIT) {
		ret = -EINVAL;
		goto out_with_lock;
	}

	if(q->uacce->ops->start_queue) {
		ret = q->uacce->ops->start_queue(q);
		if (ret < 0)
			goto out_with_lock;
	}

	q->state = UACCE_Q_STARTED;
	ret = 0;
out_with_lock:
	mutex_unlock(&uacce_mutex);

	return ret;
}

static int uacce_put_queue(struct uacce_queue *q)
{
	struct uacce_device *uacce = q->uacce;
	struct device *dev = uacce->parent;

	mutex_lock(&uacce_mutex);

	if (!q->filep)
		goto out;
	
	if (q->state == UACCE_Q_ZOMBIE) {
		dev_err(dev, "uacce Q state(%d) error!\n", q->state);
		goto out;
	}

	if ((q->state == UACCE_Q_STARTED) && uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);
	
	if ((q->state == UACCE_Q_INIT || q->state == UACCE_Q_STARTED) &&
		 uacce->ops->put_queue)
		uacce->ops->put_queue(q);
	
	q->state = UACCE_Q_ZOMBIE;
	q->filep = NULL;

	atomic_dec(&uacce->ref);

out:
	mutex_unlock(&uacce_mutex);

	return 0;
}

static long uacce_cmd_shared_qfr(struc uacce_queue *src, int fd)
{
	struc device *dev = &src->uacce->dev;
	struct file *filep = fget(fd);
	struct uacce_queue *tgt;
	int ret = -EINVAL;

	if (!filep) {
		dev_err(dev, "filep is NULL!\n");
		return ret;
	}

	if (filep->f_op != &uacce_fops) {
		dev_err(dev, "file ops mismatch!\n");
		goto out_with_fd;
	}

	tgt = filep->private_data;
	if (!tgt) {
		dev_err(dev, "target queue is not exist!\n");
		goto out_with_fd;
	}

	mutex_lock(&uacce_mutex);
	if (tgt->state == UACCE_Q_ZOMBIE || src->state == UACCE_Q_ZOMBIE) {
		dev_err(dev, "target or source queue is zombie!\n");
		goto out_with_fd;
	}

	if (!src->qfrs[UACCE_QFRT_SS] || tgt->qfrs[UACCE_QFRT_SS]) {
		dev_err(dev, "src q's SS not exists or target q's SS exists!\n");
		goto out_with_fd;
	}

	/* In No-IOMMU mode, target queue uses default SS qfr */
	tgt->qfrs[UACCE_QFRT_SS] = &noiommu_ss_default_qfr;

	ret = 0;

out_with_fd:
	mutex_unlock(&uacce_mutex);
	fput(filep);

	return ret;
}

static long uacce_get_ss_dma(struct uacce_queue *q, void __usr *arg)
{
	struct uacce_device *uacce = q->uacce;
	struct uacce_dma_slice *slice;
	unsigned long slice_idx = 0;
	unsigned long dma, size;
	unsigned int max_idx;
	long ret = -EFAULT;

	if (q->state == UACCE_Q_ZOMBIE) {
		dev_err(&uacce->dev, "queue is zombie!\n");
		ret = -EINVAL;
		goto param_check;
	}

	if (!q->qfrs[UACCE_QFRT_SS]) {
		dev_err(&uacce->dev, "no ss dma region!\n");
		ret = -EINVAL;
		goto param_check;
	}

	slice = q->qfrs[UACCE_QFRT_SS]->dma_list;
	if (copy_from_usr(&slice_idx, arg, sizeof(unsigned long))) {
		dev_err(&uacce->dev, "copy_from_user fail!\n");
		goto param_check;
	}

	if(slice[0].total_num - 1 < slice_idx) {
		dev_err(&uacce->dev, "no ss slice idx %lu err, total %u!\n",
			slice_idx, slice[0].total_num);
		ret = -EINVAL;
		goto param_check;
	}

	dma = slice[slice_idx].dma;
	size = slice[slice_idx].size;
	if (!size) {
		max_idx = slice[0].total_num - 1;
		dev_err(&uacce->dev, "%luth ss region[0x%lx, %lu] no exist, range[[0](0x%llx, %llu) -> [%u](0x%llx, %llu)]\n",
			slice_idx, dma, size,
			slice[0].dma, slice[0].size, max_idx,
			slice[max_idx].dma, slice[max_idx].size);
		ret = -ENODEV;
		goto param_check;
	}
	dma = dma | ((size >> UACCE_GRAN_SHIFT) & UACCE_GRAN_NUM_MASK);
	if (copy_to_user(arg, &dma, sizeof(unsigned long))) {
		dev_err(&uacce->dev, "copy_from_user fail!\n");
		goto param_check;
	}

	ret = (long)(slice[0].total_num - 1 - slice_idx);

param_check:
	return ret;
}

static void uacce_free_dma_buffers(struct uacce_queue *q)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	struct device *pdev = q->uacce->parent;
	int i = 0;

	if (!qfr->dma_list)
		return;
	while (i < qfr->dma_list[0].total_num) {
		WARN_ON(!qfr->dma_list[i].size || !qfr->dma_list[i].dma);
		dev_dbg(pdev, "free dma qfr (kaddr=%lx, dma=%llx)\n",
			(unsigned long)qfr->dma_list[i].kaddr,
			qfr->dma_list[i].dma);
		dma_free_coherent(uacce->pdev, qfr->dma_list[i].size,
				  qfr->dma_list[i].kaddr,
				  qfr->dma_list[i].dma);
		i++;
	}
	kfree(qfr->dma_list);
	qfr->dma_list = NULL;
}

/**
 * uacce_wake_up - Wake up the process who is waiting this queue
 * @q the accelerator queue to wake up
 */
void uacce_wake_up(struct uacce_queue *q)
{
	if (unlikely(!q))
		return;

	wake_up_interruptible(&q->wait);
}
EXPORT_SYMBOL_GPL(uacce_wake_up);

static long uacce_fops_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_device *uacce = q->uacce;

	switch (cmd) {
	case UACCE_CMD_START_Q:
		return uacce_start_queue(q);

	case UACCE_CMD_PUT_Q:
		return uacce_put_queue(q);

	case UACCE_CMD_SHARE_SVAS:
		return uacce_cmd_share_qfr(q, (int)arg);
		
	case UACCE_CMD_GET_SS_DMA:
		return uacce_get_ss_dma(q, (void __user *)(uintptr_t)arg);
	default:
		if (!uacce->ops->ioctl)
			return -EINVAL;

		return uacce->ops->ioctl(q, cmd, arg);
	}
}

#ifdef CONFIG_COMPAT
static long uacce_fops_compat_ioctl(struct file *filep,
				    unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)(uintptr_t)compat_ptr(arg);

	return uacce_fops_unl_ioctl(filep, cmd, arg);
}
#endif

static int uacce_bind_queue(struct uacce_device *uacce, struct uacce_queue *q)
{
	u32 pasid;
	struct iommu_sva *handle;

	if (!(uacce->flags & UACCE_DEV_SVA))
		return 0;
	
	handle = iommu_sva_bind_device(uacce->parent, current->mm, NULL);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	
	pasid = iommu_sva_get_pasid(handle);
	if (pasid == IOMMU_PASID_INVALID) {
		iommu_sva_unbind_device(handle);
		return -ENODEV;
	}

	q->handle = handle;
	q->pasid = pasid;
	return 0;
}

static void uacce_unbind_queue(struct uacce_queue *q)
{
	if (!q->handle)
		return;
	iommu_sva_unbind_device(q->handle);
	q->handle = NULL;
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce_device *uacce;
	struct uacce_queue *q;
	int ret;

	uacce = xa_load(&uacce_xa, iminor(inode));
	if (!uacce)
		return -ENODEV;

	q = kzalloc(sizeof(struct uacce_queue), GFP_KERNEL);
	if (!q)
		return -ENOMEM;
	
	ret = uacce_bind_queue(uacce, q);
	if (ret)
		goto out_with_mem;

	q->uacce = uacce;
	q->filep = filep;

	if (uacce->ops->get_queue) {
		ret = uacce->ops->get_queue(uacce, q->pasid, q);
		if (ret < 0)
			goto out_with_bond;
	}

	atomic_inc(&uacce->ref);
	init_waitqueue_head(&q->wait);
	filep->private_data = q;
	uacce->inode = inode;
	q->state = UACCE_Q_INIT;

	mutex_lock(&uacce->queues_lock);
	list_add(&q->list, &uacce->queues);
	mutex_unlock(&uacce->queues_lock);

	return 0;

out_with_bond:
	uacce_unbind_queue(q);
out_with_mem:
	kfree(q);
	return ret;
}

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_qfile_region *ss = q->qfrs[UACCE_QFRT_SS];

	mutex_lock(&q->uacce->queues_lock);
	list_del(&q->list);
	mutex_unlock(&q->uacce->queues_lock);
	uacce_put_queue(q);
	uacce_unbind_queue(q);

	if (ss && ss != &noiommu_ss_default_qfr) {
		uacce_free_dma_buffers(q);
		kfree(ss);
	}

	kfree(q);

	return 0;
}

static vm_fault_t uacce_vma_fault(struct vm_fault *vmf)
{
	if (vmf->flags & (FAULT_FLAGS_MKWRITE | FAULT_FALG_WRITE))
		return VM_FAULT_SIGBUS;

	return 0;
}

static void uacce_vma_close(struct vm_area_struct *vma)
{
	struct uacce_queue *q = vma->vm_private_data;
	struct uacce_qfile_region *qfr = NULL;
	struct uacce_device *uacce = q->uacce;
	struct device *dev = &q->uacce->dev;

	if (vma->vm_pgoff >= UACCE_MAX_REGION)
		return;
	
	qfr = q->qfr[vma->vm_pgoff];
	if (!qfr) {
		dev_err(dev, "qfr NULL, type %lu!\n", vma->vm_pgoff);
		return;
	}

	if (qfr->type == UACCE_QFRT_SS &&
		atomic_read(&current->active_mm->mm_users) > 0) {
		if ((q->state == UACCE_Q_STARTED) && uacce->ops->stop_queue)
			uacce->ops->stop_queue(q);
		uacce_free_dma_buffers(q);
		kfree(qfr);
		q->qfrs[vma->vm_pgoff] = NULL;
	} else if (qfr->type != UACCE_QFRT_SS) {
		kfree(qfr);
		q->qfrs[vma->vm_pgoff] = NULL;
	}
}

static const struct vm_operations_struct uacce_vm_ops = {
	.fault = uacce_vma_fault,
	.close = uacce_vma_close,
};

static int get_sort_base(struct uacce_dma_slice *list, int low, int high,
			 struct uacce_dma_slice *tmp)
{
	tmp->kaddr = list[low].kaddr;
	tmp->size = list[low].size;
	tmp->dma = list[low].dma;

	if (low > high)
		return -EINVAL;
	else if (low == high)
		return 0;

	while (low < high) {
		while (low < high && list[high].dma > tmp->dma)
			high--;
		list[low].kaddr = list[high].kaddr;
		list[low].dma = list[high].dma;
		list[low].size = list[high].size;
		while (low < high && list[low].dma < tmp->dma)
			low++;
		list[high].kaddr = list[low].kaddr;
		list[high].dma = list[low].dma;
		list[high].size = list[low].size;
	}
	list[low].kaddr = tmp->kaddr;
	list[low].dma = tmp->dma;
	list[low].size = tmp->size;

	return low;
}

static int uacce_sort_dma_buffers(struct uacce_dma_slice *list, int low,
				   int high, struct uacce_dma_slice *tmp)
{
	int *idx_list;
	int top = 0;
	int pilot;

	idx_list = kcalloc(list[0].total_num, sizeof(int),
			   GFP_KERNEL | __GFP_ZERO);
	if (!idx_list)
		return -ENOMEM;

	pilot = get_sort_base(list, low, high, tmp);
	if (pilot <= 0) {
		if (pilot)
			pr_err("fail to sort base!\n");
		kfree(idx_list);
		return;
	}

	if (pilot > low + 1) {
		idx_list[top++] = low;
		idx_list[top++] = pilot - 1;
	}
	if (pilot < high - 1) {
		idx_list[top++] = pilot + 1;
		idx_list[top++] = high;
	}
	while (top > 0) {
		high = idx_list[--top];
		low = idx_list[--top];
		pilot = get_sort_base(list, low, high, tmp);
		if (pilot > low + 1) {
			idx_list[top++] = low;
			idx_list[top++] = pilot - 1;
		}
		if (pilot < high - 1) {
			idx_list[top++] = pilot + 1;
			idx_list[top++] = high;
		}
	}

	kfree(idx_list);
	return 0;
}

static int uacce_alloc_dma_buffers(struct uacce_queue *q,
				   struct vm_area_struct *vma)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long max_size = PAGE_SIZE << (MAX_ORDER - 1);
	struct device *pdev = q->uacce->parent;
	struct uacce_device *uacce = q->uacce
	unsigned long start = vma->vm_start;
	struct uacce_dma_slice *slice;
	unsigned long ss_sum;
	int ret, i;

	/*
	 * when IOMMU closed, set maximum slice size is 128M, default is 4M
	 * when IOMMU opened, set maximum slice size based on actual size
	 */
	if (uacce->flags & UACCE_DEV_IOMMU)
		max_size = size;
	else if (max_size > UACCE_GRAN_NUM_MASK << UACCE_GRAN_SHIFT)
		max_size = (UACCE_GRAN_NUM_MASK + 1) << (UACCE_GRAN_SHIFT - 1);

	ss_num = size / max_size + (size % max_size ? 1 : 0);
	slice = kcalloc(ss_num + 1, sizeof(*slice), GFP_KERNEL | __GFP_ZERO);
	if (!slice)
		return -ENOMEM;

	qfr->dma_list = slice;
	for (i = 0; i < ss_num; i++) {
		if (start + max_size > vma->vm_end)
			size = vma->vm_end - start;
		else
			size = max_size;
		dev_dbg(pdev, "allocate dma %ld pages\n",
			(size + PAGE_SIZE - 1) >> PAGE_SHIFT);
		slice[i].kaddr = dma_alloc_coherent(pdev, (size +
						    PAGE_SIZE - 1) & PAGE_MASK,
						    &slice[i].dma, GFP_KERNEL);
		if (!slice[i].kaddr) {
			dev_err(pdev, "alloc dma slice(sz=%ld,dma=0x%llx) fail!\n",
			size, size[i].dma);
			slice[0].total_num = i;
			uacce_free_dma_buffers(q);
			return -ENOMEM;
		}
		slice[i].size = (size + PAGE_SIZE - 1) & PAGE_MASK;
		slice[i].total_num = ss_num;
		start += size;
	}

	ret = uacce_sort_dma_buffers(slice, 0, slice[0].total_num - 1,
			       	&slice[ss_num]);
	if (ret) {
		dev_err(pdev, "failed to sort dma buffers.\n");
		uacce_free_dma_buffers(q);
		return ret;
	}

	return 0;
}

static int uacce_mmap_dma_buffers(struct uacce_queue *q,
				  struct vm_area_struct *vma)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	struct uacce_dma_slice *slice = qfr->dma_list;
	struct device *pdev = q->uacce->parent;
	unsigned long vm_pgoff;
	int ret = 0;
	int i = 0;

	/*
	 * dma_mmap_coherent() requires vm_pgoff as 0
	 * restore vm_pfoff to initial value for mmap()
	 */
	vm_pgoff = vma->vm_pgoff;
	vma->vm_pgoff = 0;
	while (i < slice[0].total_num && slice[i].size) {
		vma->vm_end = vma->vm_start + slice[i].size;
		ret = dma_mmap_coherent(pdev, vma, slice[i].kaddr,
					slice[i].dma,
					slice[i].size);
		if (ret) {
			dev_err(pdev, "mmap dma buf fail(dma=0x%llx,size=0x%llx)!\n",
				slice[i].dma, slice[i].size);
			goto DMA_MMAP_FAIL;
		}

		i++;
		vma->vm_start = vma->vm_end;
	}

	/* System unmap_region will clean the results, we need do nothing */
DMA_MMAP_FAIL:
	vma->vm_pgoff = vm_pgoff;
	vma->vm_start = qfr->iova;
	vma->vm_end = vma->vm_start + (qfr->nr_pages << PAGE_SHIFT);

	return ret;
}

static int uacce_create_region(struct uacce_queue *q,
					struct vm_area_struct *vma,
					struct uacce_qfile_region *qfr)
{
	int ret;

	qfr->iova = vma->vm_start;
	qfr->nr_pages = vma_pages(vma);

	/* allocate memory */
	ret = uacce_alloc_dma_buffers(q, vma);
	if (ret)
		return ret;
	
	ret = uacce_mmap_dma_buffers(q, vma);
	if (ret)
		goto err_with_pages;
	
	return ret;

err_with_pages:
	uacce_free_dma_buffers(q);
	return ret;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_device *uacce = q->uacce;
	enum uacce_qfrt type = UACCE_MAX_REGION;
	struct uacce_qfile_region *qfr;
	int ret = -EINVAL;

	if (vma->vm_pgoff < UACCE_MAX_REGION)
		type = vma->vm_pgoff;
	else
		return ret;
	
	if (q->qfrs[type])
		return -EEXIST;
	
	qfr = kzalloc(sizeof(*qfr), GFP_KERNEL);
	if (!qfr)
		return -ENOMEM;
	
	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_WIPEONFORK;
	vma->vm_ops = &uacce_vm_ops;
	vma->vm_private_data = q;
	qfr->type = type;

	mutex_lock(&uacce_mutex);

	if (q->state != UACCE_Q_INIT && q->state != UACCE_Q_STARTED)
		goto out_with_lock;
	
	q->qfr[type] = qfr;

	switch (type) {
	case UACCE_QFRT_MMIO:
	case UACCE_QFRT_DUS:
		if (!uacce->ops->mmap) 
			goto out_with_lock;

		ret = uacce->ops->mmap(q, vma, qfr);
		if (ret)
			goto out_with_lock;
		break;
	
	case UACCE_QFRT_SS:
		ret = uacce_create_region(q, vma, qfr);
		if (ret)
			goto out_with_lock;
		break;

	default:
		ret = -EINVAL;
		goto out_with_lock;
	}

	mutex_lock(&uacce_mutex);

	return ret;

out_with_lock:
	mutex_lock(&uacce_mutex);
	kfree(qfr);
	q->qfrs[type] = NULL
	return ret;
}

static __poll_t uacce_fops_poll(struct file *file, poll_table *wait)
{
	struct uacce_queue *q = file->private_data;
	struct uacce_device *uacce = q->uacce;

	poll_wait(file, &q->wait, wait);
	if (uacce->ops->is_q_updated && uacce->ops->is_q_updated(q))
		ret = EPOLLIN | EPOLLRDNORM;

	return 0;
}

static const struct file_operations uacce_fops = {
	.owner		= THIS_MODULE,
	.open		= uacce_fops_open,
	.release	= uacce_fops_release,
	.unlocked_ioctl	= uacce_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= uacce_fops_compat_ioctl,
#endif
	.mmap		= uacce_fops_mmap,
	.poll		= uacce_fops_poll,
};

#define to_uacce_device(dev) container_of(dev, struct uacce_device, dev);

static ssize_t api_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%s\n", uacce->api_ver);
}

static ssize_t flags_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%d\n", uacce->flags);
}

static ssize_t available_instances_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	if (!uacce->ops->get_available_instances)
		return -ENODEV;

	return sysfs_emit(buf, "%d\n",
			   uacce->ops->get_available_instances(uacce));
}

static ssize_t algorithms_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%s", uacce->algs);
}

static ssize_t region_mmio_size_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%lu\n",
				uacce->qf_pg_num[UACCE_QFRT_MMIO] << PAGE_SHIFT);
}

static ssize_t region_dus_size_show(struct device *dev,
					 struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%lu\n",
				uacce->qf_pg_num[UACCE_QFRT_DUS] << PAGE_SHIFT);
}

static ssize_t isolate_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%d\n", atomic_read(&uacce->isolate->is_isolate));
}

static ssize_t isolate_strategy_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%u\n", uacce->isolate->hw_err_isolate_hz);
}

static ssize_t isolate_strategy_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct uacce_device *uacce = to_uacce_device(dev);
	unsigned long val = 0;

#define MAX_ISOLATE_STRATEGY	65535

	/* must be set by PF */
	if (uacce->is_vf)
		return -EINVAL;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val > MAX_ISOLATE_STRATEGY)
		return -EINVAL;

	if (atomic_read(&uacce->ref))
		return -EBUSY;

	uacce->isolate->hw_err_isolate_hz = val;
	dev_info(uacce->parent,
		"the value of isolate_strategy is set to %lu.\n", val);

	return count;
}

static ssize_t dev_state_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%d\n", uacce->ops->get_dev_state(uacce));
}

static ssize_t node_id_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);
	int node_id = -1;

#ifdef CONFIG_NUMA
	node_id = uacce->parent->numa_node;
#endif
	return sysfs_emit(buf, "%d\n", node_id);
}

static ssize_t numa_distance_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);
	int distance = 0;

#ifdef CONFIG_NUMA
	distance = node_distance(uacce->parent->numa_node,
		cpu_to_node(smp_processor_id()));
#endif
	return sysfs_emit(buf, "%d\n", abs(distance));
}

static DEVICE_ATTR_RO(api);
static DEVICE_ATTR_RO(flags);
static DEVICE_ATTR_RO(node_id);
static DEVICE_ATTR_RO(available_instances);
static DEVICE_ATTR_RO(algorithms);
static DEVICE_ATTR_RO(region_mmio_size);
static DEVICE_ATTR_RO(region_dus_size);
static DEVICE_ATTR_RO(isolate);
static DEVICE_ATTR_RO(isolate_strategy);
static DEVICE_ATTR_RO(dev_state);
static DEVICE_ATTR_RO(numa_distance);

static struct attribute *uacce_dev_attrs[] = {
	&dev_attr_api.attr,
	&dev_attr_flags.attr,
	&dev_attr_node_id.attr,
	&dev_attr_available_instances.attr,
	&dev_attr_algorithms.attr,
	&dev_attr_region_mmio_size.attr,
	&dev_attr_region_dus_size.attr,
	&dev_attr_isolate.attr,
	&dev_attr_isolate_strategy.attr,
	&dev_attr_dev_state.attr,
	&dev_attr_numa_distance.attr,
	NULL,
};

static umode_t uacce_dev_is_visible(struct kobject *kobj,
					struct attribute *attr, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct uacce_device *uacce = to_uacce_device(dev);

	if (((attr == &dev_attr_region_mmio_size.attr) &&
		(!uacce->qf_pg_num[UACCE_QFRT_MMIO])) ||
		((attr == &dev_attr_region_dus_size.attr) &&
		(!uacce->qf_pg_num[UACCE_QFRT_DUS])))
		return 0;

	return attr->mode;
}

static struct attribute_group uacce_dev_group = {
	.is_visible = uacce_dev_is_visible,
	.attrs		= uacce_dev_attrs,
};

__ATTRIBUTE_GROUPS(uacce_dev);

static void uacce_release(struct device *dev)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	kfree(uacce);
}

static unsigned int uacce_enable_sva(struct device *parent, unsigned int flags)
{
	int ret;

	if (!(flags & UACCE_DEV_SVA))
		return flags;

	flags &= ~UACCE_DEV_SVA;

	ret = iommu_dev_enable_feature(parent, IOMMU_DEV_FEAT_IOPF);
	if (ret) {
		dev_err(parent, "failed to enable IOPF feature! ret = %pe\n", ERR_PTR(ret));
		return flags;
	}
	
	ret = iommu_dev_enable_feature(parent, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		dev_err(parent, "failed to enable SVA feature! ret = %pe\n", ERR_PTR(ret));
		iommu_dev_disable_feature(parent, IOMMU_DEV_FEAT_IOPF)
		return flags;
	}

	return flags | UACCE_DEV_SVA;
}

static void uacce_disable_sva(struct uacce_device *uacce)
{
	if (!(uacce->flags & UACCE_DEV_SVA))
		return;
	
	iommu_dev_disable_feature(uacce->parent, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(uacce->parent, IOMMU_DEV_FEAT_IOPF);
}

/**
 * uacce_alloc() - alloc an accelerator
 * @parent: pointer of uacce parent device
 * @interface: pointer of uacce_interface for register
 *
 * Returns uacce pointer if success and ERR_PTR if not
 * Need check returned negotiated uacce->flags
 */
 struct uacce_device *uacce_alloc(struct device *parent,
 				 struct uacce_interface *interface)
{
	unsigned int flags = interface->flags;
	struct uacce_device *uacce;
	int ret;

	uacce = kzalloc(sizeof(struct uacce_device), GFP_KERNEL);
	if (!uacce)
		return ERR_PTR(-ENOMEM);

	flags = uacce_enable_sva(parent, flags);

	uacce->parent = parent;
	uacce->flags = flags;
	uacce->ops = interface->ops;

	ret = xa_alloc(&uacce_xa, &uacce->dev_id, uacce, xa_limit_32b,
			   GFP_KERNEL);
	if (ret < 0)
		goto err_with_uacce;
	INIT_LIST_HEAD(&uacce->queues);
	INIT_LIST_HEAD(&uacce->isolate_data.hw_errs);

	mutex_init(&uacce->queues_lock);
	device_initialize(&uacce->dev);
	uacce->dev.devt = MKDEV(MAJOR(uacce_devt), uacce->dev_id);
	uacce->dev.
	uacce->dev.
	uacce->dev.
	uacce->dev.

}
static bool uacce_q_avail_ioctl(struct uacce_queue *q, unsigned int cmd)
{
	enum uacce_q_state state = q->state;
	bool avail = false;

	switch (state) {
	case UACCE_Q_INIT:
		switch (cmd) {
		case UACCE_CMD_SHARE_SVAS:
		case UACCE_CMD_GET_SS_DMA:
		case UACCE_CMD_PUT_Q:
			avail = true;
			break;
		case UACCE_CMD_START:
			if (q->qfrs[UACCE_QFRT_MMIO] &&
			    q->qfrs[UACCE_QFRT_DUS])
				avail = true;
			break;
		/* acc specific ioctl */
		default:
			avail = true;
		}
		break;
	case UACCE_Q_STARTED:
		switch (cmd) {
		case UACCE_CMD_SHARE_SVAS:
		case UACCE_CMD_GET_SS_DMA:
		case UACCE_CMD_PUT_Q:
			avail = true;
			break;
		case UACCE_CMD_START:
			break;
		default:
			avail = true;
		}
		break;
	case UACCE_Q_ZOMBIE:
		break;
	default:
		break;
	}

	return avail;
}

static bool uacce_q_avail_mmap(struct uacce_queue *q, unsigned int type)
{
	enum uacce_q_state state = q->state;
	bool avail = false;

	switch (state) {
	case UACCE_Q_INIT:
		avail = true;
		break;
	case UACCE_Q_STARTED:
		switch (type) {
		case UACCE_QFRT_DKO:
		/* fix me: ss map should be done before start queue */
		case UACCE_QFRT_SS:
			avail = true;
			break;
		case UACCE_QFRT_MMIO:
		case UACCE_QFRT_DUS:
		default:
			break;
		}
		break;
	case UACCE_Q_ZOMBIE:
		break;
	default:
		break;
	}

	return avail;
}

static inline int uacce_iommu_map_qfr(struct uacce_queue *q,
				      struct uacce_qfile_region *qfr)
{
	struct device *dev = q->uacce->pdev;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	int i, j, ret;

	if (!domain)
		return -ENODEV;

	for (i = 0; i < qfr->nr_pages; i++) {
		ret = iommu_map(domain, qfr->iova + i * PAGE_SIZE,
				page_to_phys(qfr->pages[i]),
				PAGE_SIZE, qfr->prot | q->uacce->prot);
		if (ret) {
			dev_err(dev, "iommu_map page %i fail %d\n", i, ret);
			goto err_with_map_pages;
		}
		get_page(qfr->pages[i]);
	}

	return 0;

err_with_map_pages:
	for (j = i - 1; j >= 0; j--) {
		iommu_unmap(domain, qfr->iova + j * PAGE_SIZE, PAGE_SIZE);
		put_page(qfr->pages[j]);
	}
	return ret;
}

static inline void uacce_iommu_unmap_qfr(struct uacce_queue *q,
					 struct uacce_qfile_region *qfr)
{
	struct device *dev = q->uacce->pdev;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	int i;

	if (!domain || !qfr)
		return;

	for (i = qfr->nr_pages - 1; i >= 0; i--) {
		iommu_unmap(domain, qfr->iova + i * PAGE_SIZE, PAGE_SIZE);
		put_page(qfr->pages[i]);
	}
}

static int uacce_queue_map_qfr(struct uacce_queue *q,
			       struct uacce_qfile_region *qfr)
{
	/* Only IOMMU mode does this map */
	if (!(qfr->flags & UACCE_QFRF_MAP) || (qfr->flags & UACCE_QFRF_DMA))
		return 0;

	dev_dbg(&q->uacce->dev, "queue map %s qfr(npage=%ld, iova=%pK)\n",
		uacce_qfrt_str(qfr), qfr->nr_pages, (void *)qfr->iova);

	return uacce_iommu_map_qfr(q, qfr);
}

static void uacce_queue_unmap_qfr(struct uacce_queue *q,
				  struct uacce_qfile_region *qfr)
{
	if (!(qfr->flags & UACCE_QFRF_MAP) || (qfr->flags & UACCE_QFRF_DMA))
		return;

	dev_dbg(&q->uacce->dev, "queue map %s qfr(npage=%ld, iova=%pK)\n",
		uacce_qfrt_str(qfr), qfr->nr_pages, (void *)qfr->iova);

	uacce_iommu_unmap_qfr(q, qfr);
}

#ifndef CONFIG_UACCE_FIX_MMAP
static vm_fault_t uacce_shm_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct uacce_qfile_region *qfr;
	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	vm_fault_t ret;

	uacce_qs_rlock();

	qfr = vma->vm_private_data;
	if (!qfr) {
		pr_info("this page is not valid to user space\n");
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	pr_debug("uacce: fault on %s qfr page %ld/%ld\n", uacce_qfrt_str(qfr),
		 page_offset, qfr->nr_pages);

	if (page_offset >= qfr->nr_pages) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	get_page(qfr->pages[page_offset]);
	vmf->page = qfr->pages[page_offset];
	ret = 0;

out:
	uacce_qs_runlock();
	return ret;
}

static const struct vm_operations_struct uacce_shm_vm_ops = {
	.fault = uacce_shm_vm_fault,
};
#endif

static int uacce_qfr_alloc_pages(struct uacce_qfile_region *qfr)
{
	gfp_t gfp_mask = GFP_ATOMIC | __GFP_ZERO;
	int i, j;

	qfr->pages = kcalloc(qfr->nr_pages, sizeof(*qfr->pages), gfp_mask);
	if (!qfr->pages)
		return -ENOMEM;

	for (i = 0; i < qfr->nr_pages; i++) {
		qfr->pages[i] = alloc_page(gfp_mask);
		if (!qfr->pages[i])
			goto err_with_pages;
	}

	return 0;

err_with_pages:
	for (j = i - 1; j >= 0; j--)
		put_page(qfr->pages[j]);

	kfree(qfr->pages);
	return -ENOMEM;
}

static void uacce_qfr_free_pages(struct uacce_qfile_region *qfr)
{
	int i;

	for (i = 0; i < qfr->nr_pages; i++)
		put_page(qfr->pages[i]);

	kfree(qfr->pages);
}

static inline int uacce_queue_mmap_qfr(struct uacce_queue *q,
				       struct uacce_qfile_region *qfr,
				       struct vm_area_struct *vma)
{
#ifdef CONFIG_UACCE_FIX_MMAP
	int i, ret;

	if (qfr->nr_pages)
		dev_dbg(q->uacce->pdev, "mmap qfr (page ref=%d)\n",
			page_ref_count(qfr->pages[0]));
	for (i = 0; i < qfr->nr_pages; i++) {
		get_page(qfr->pages[i]);
		ret = remap_pfn_range(vma, vma->vm_start + i * PAGE_SIZE,
				      page_to_pfn(qfr->pages[i]), PAGE_SIZE,
				      vma->vm_page_prot);
		if (ret) {
			dev_err(q->uacce->pdev,
				"remap_pfm_range fail(nr_pgs=%lx)!\n",
				qfr->nr_pages);
			return ret;
		}
	}

#else
	vma->vm_private_data = qfr;
	vma->vm_ops = &uacce_shm_vm_ops;
#endif

	return 0;
}

static void uacce_free_dma_buffers(struct uacce_queue *q)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	struct uacce *uacce = q->uacce;
	int i = 0;

	if (!qfr->dma_list)
		return;
	while (i < qfr->dma_list[0].total_num) {
		WARN_ON(!qfr->dma_list[i].size || !qfr->dma_list[i].dma);
		dev_dbg(uacce->pdev, "free dma qfr %s (kaddr=%lx, dma=%llx)\n",
			uacce_qfrt_str(qfr),
			(unsigned long)qfr->dma_list[i].kaddr,
			qfr->dma_list[i].dma);
		dma_free_coherent(uacce->pdev, qfr->dma_list[i].size,
				  qfr->dma_list[i].kaddr,
				  qfr->dma_list[i].dma);
		i++;
	}
	kfree(qfr->dma_list);
	qfr->dma_list = NULL;
}

static int get_sort_base(struct uacce_dma_slice *list, int low, int high,
			 struct uacce_dma_slice *tmp)
{
	tmp->kaddr = list[low].kaddr;
	tmp->size = list[low].size;
	tmp->dma = list[low].dma;

	if (low >= high)
		return -EINVAL;
	while (low < high) {
		while (low < high && list[high].dma > tmp->dma)
			high--;
		list[low].kaddr = list[high].kaddr;
		list[low].dma = list[high].dma;
		list[low].size = list[high].size;
		while (low < high && list[low].dma < tmp->dma)
			low++;
		list[high].kaddr = list[low].kaddr;
		list[high].dma = list[low].dma;
		list[high].size = list[low].size;
	}
	list[low].kaddr = tmp->kaddr;
	list[low].dma = tmp->dma;
	list[low].size = tmp->size;

	return low;
}

static void uacce_sort_dma_buffers(struct uacce_dma_slice *list, int low,
				   int high, struct uacce_dma_slice *tmp)
{
	int pilot, top = 0;
	int *idx_list;

	idx_list = kcalloc(list[0].total_num, sizeof(int),
			   GFP_KERNEL | __GFP_ZERO);
	if (!idx_list)
		return;

	pilot = get_sort_base(list, low, high, tmp);
	if (pilot < 0) {
		kfree(idx_list);
		return;
	}
	if (pilot > low + 1) {
		idx_list[top++] = low;
		idx_list[top++] = pilot - 1;
	}
	if (pilot < high - 1) {
		idx_list[top++] = pilot + 1;
		idx_list[top++] = high;
	}
	while (top > 0) {
		high = idx_list[--top];
		low = idx_list[--top];
		pilot = get_sort_base(list, low, high, tmp);
		if (pilot > low + 1) {
			idx_list[top++] = low;
			idx_list[top++] = pilot - 1;
		}
		if (pilot < high - 1) {
			idx_list[top++] = pilot + 1;
			idx_list[top++] = high;
		}
	}

	kfree(idx_list);
}

static int uacce_alloc_dma_buffers(struct uacce_queue *q,
				   struct vm_area_struct *vma)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long max_size = PAGE_SIZE << (MAX_ORDER - 1);
	unsigned long start = vma->vm_start;
	struct uacce *uacce = q->uacce;
	struct uacce_dma_slice *slice;
	int i, ss_num;

	/* Set maximum slice size is 128MB */
	if (max_size > UACCE_GRAN_NUM_MASK << UACCE_GRAN_SHIFT)
		max_size = (UACCE_GRAN_NUM_MASK + 1) << (UACCE_GRAN_SHIFT - 1);

	ss_num = (size + max_size - 1) / max_size;
	slice = kcalloc(ss_num + 1, sizeof(*slice), GFP_KERNEL | __GFP_ZERO);
	if (!slice)
		return -ENOMEM;

	qfr->dma_list = slice;
	for (i = 0; i < ss_num; i++) {
		if (start + max_size > vma->vm_end)
			size = vma->vm_end - start;
		else
			size = max_size;
		dev_dbg(uacce->pdev, "allocate dma %ld pages\n",
			(size + PAGE_SIZE - 1) >> PAGE_SHIFT);
		slice[i].kaddr = dma_alloc_coherent(uacce->pdev, (size +
						    PAGE_SIZE - 1) & PAGE_MASK,
						    &slice[i].dma, GFP_KERNEL);
		if (!slice[i].kaddr) {
			dev_err(uacce->pdev, "alloc dma slice(sz=%ld) fail!\n",
				size);
			slice[0].total_num = i;
			return -ENOMEM;
		}
		slice[i].size = (size + PAGE_SIZE - 1) & PAGE_MASK;
		slice[i].total_num = ss_num;
		start += size;
	}

	uacce_sort_dma_buffers(slice, 0, slice[0].total_num - 1,
			       &slice[ss_num]);

	return 0;
}

static int uacce_mmap_dma_buffers(struct uacce_queue *q,
				  struct vm_area_struct *vma)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	struct uacce_dma_slice *slice = qfr->dma_list;
	struct uacce *uacce = q->uacce;
	unsigned long vm_pgoff;
	int ret = 0;
	int i = 0;

	/*
	 * dma_mmap_coherent() requires vm_pgoff as 0
	 * restore vm_pfoff to initial value for mmap()
	 */
	vm_pgoff = vma->vm_pgoff;
	vma->vm_pgoff = 0;
	while (i < slice[0].total_num && slice[i].size) {
		vma->vm_end = vma->vm_start + slice[i].size;
		ret = dma_mmap_coherent(uacce->pdev, vma, slice[i].kaddr,
					slice[i].dma,
					slice[i].size);
		if (ret) {
			dev_err(uacce->pdev,
				"mmap dma buf fail(dma=0x%llx,size=0x%x)!\n",
				slice[i].dma, slice[i].size);
			goto DMA_MMAP_FAIL;
		}

		i++;
		vma->vm_start = vma->vm_end;
	}

	/* System unmap_region will clean the results, we need do nothing */
DMA_MMAP_FAIL:
	vma->vm_pgoff = vm_pgoff;
	vma->vm_start = qfr->iova;
	vma->vm_end = vma->vm_start + (qfr->nr_pages << PAGE_SHIFT);

	return ret;
}

static int uacce_mmap_region(u32 flags, struct uacce_queue *q,
			     struct vm_area_struct *vma,
			     struct uacce_qfile_region *qfr)
{
	struct uacce *uacce = q->uacce;
	int ret;

	if (flags & UACCE_QFRF_SELFMT)
		return uacce->ops->mmap(q, vma, qfr);

	/* map to device */
	if (!(flags & UACCE_QFRF_SELFMT)) {
		ret = uacce_queue_map_qfr(q, qfr);
		if (ret)
			return ret;
	}

	/* mmap to user space */
	if (flags & UACCE_QFRF_MMAP) {
		if (flags & UACCE_QFRF_DMA)
			ret = uacce_mmap_dma_buffers(q, vma);
		else
			ret = uacce_queue_mmap_qfr(q, qfr, vma);
		if (ret) {
			uacce_queue_unmap_qfr(q, qfr);
			return ret;
		}
	}

	return 0;
}

static struct
uacce_qfile_region *uacce_create_region(struct uacce_queue *q,
					struct vm_area_struct *vma,
					enum uacce_qfrt type, u32 flags)
{
	struct uacce_qfile_region *qfr;
	struct uacce *uacce = q->uacce;
	int ret = -ENOMEM;

	qfr = kzalloc(sizeof(*qfr), GFP_ATOMIC);
	if (!qfr)
		return ERR_PTR(ret);

	qfr->type = type;
	qfr->flags = flags;
	qfr->iova = vma->vm_start;
	qfr->nr_pages = vma_pages(vma);
	q->qfrs[type] = qfr;

	if (vma->vm_flags & VM_READ)
		qfr->prot |= IOMMU_READ;

	if (vma->vm_flags & VM_WRITE)
		qfr->prot |= IOMMU_WRITE;

	/* allocate memory */
	if (flags & UACCE_QFRF_DMA) {
		ret = uacce_alloc_dma_buffers(q, vma);
		if (ret) {
			uacce_free_dma_buffers(q);
			goto err_with_qfr;
		}
	} else if (!(flags & UACCE_QFRF_SELFMT)) {
		ret = uacce_qfr_alloc_pages(qfr);
		if (ret) {
			dev_err(uacce->pdev, "alloc page fail!\n");
			goto err_with_qfr;
		}
	}

	ret = uacce_mmap_region(flags, q, vma, qfr);
	if (ret) {
		dev_err(uacce->pdev, "uacce mmap region fail!\n");
		goto err_with_pages;
	}

	return qfr;

err_with_pages:
	if (flags & UACCE_QFRF_DMA)
		uacce_free_dma_buffers(q);
	else if (!(flags & UACCE_QFRF_SELFMT))
		uacce_qfr_free_pages(qfr);
err_with_qfr:
	kfree(qfr);
	q->qfrs[type] = NULL;
	return ERR_PTR(ret);
}

static struct uacce_qfile_region noiommu_ss_default_qfr = {
	.type	=	UACCE_QFRT_SS,
	.flags	=	UACCE_QFRF_DMA,
};

/* we assume you have uacce_queue_unmap_qfr(q, qfr) from all related queues */
static void uacce_destroy_region(struct uacce_queue *q,
				 struct uacce_qfile_region *qfr)
{
	struct uacce *uacce = q->uacce;

	if (qfr->flags & UACCE_QFRF_DMA) {
		uacce_free_dma_buffers(q);
	} else if (qfr->pages) {
		if (qfr->flags & UACCE_QFRF_KMAP && qfr->kaddr) {
			dev_dbg(uacce->pdev, "vunmap qfr %s\n",
				uacce_qfrt_str(qfr));
			vunmap(qfr->kaddr);
			qfr->kaddr = NULL;
		}

		uacce_qfr_free_pages(qfr);
	}
	if (qfr != &noiommu_ss_default_qfr)
		kfree(qfr);
}

static long uacce_cmd_share_qfr(struct uacce_queue *src, int fd)
{
	struct device *dev = &src->uacce->dev;
	struct file *filep = fget(fd);
	struct uacce_queue *tgt;
	int ret = -EINVAL;

	if (!filep) {
		dev_err(dev, "filep is NULL!\n");
		return ret;
	}

	if (filep->f_op != &uacce_fops) {
		dev_err(dev, "file ops mismatch!\n");
		goto out_with_fd;
	}

	tgt = filep->private_data;
	if (!tgt) {
		dev_err(dev, "target queue is not exist!\n");
		goto out_with_fd;
	}

	/* no SVA is needed if the dev can do fault-from-dev */
	if (tgt->uacce->flags & UACCE_DEV_FAULT_FROM_DEV) {
		dev_err(dev, "No need to share in SVA device\n");
		goto out_with_fd;
	}

	dev_dbg(&src->uacce->dev, "share ss with %s\n",
		dev_name(&tgt->uacce->dev));

	if (!src->qfrs[UACCE_QFRT_SS] || tgt->qfrs[UACCE_QFRT_SS]) {
		dev_err(dev, "src q's SS not exists or target q's SS exists!\n");
		goto out_with_fd;
	}

	ret = uacce_queue_map_qfr(tgt, src->qfrs[UACCE_QFRT_SS]);
	if (ret)
		goto out_with_fd;

	/* In No-IOMMU mode, taget queue uses default SS qfr */
	if (src->qfrs[UACCE_QFRT_SS]->flags & UACCE_QFRF_DMA) {
		tgt->qfrs[UACCE_QFRT_SS] = &noiommu_ss_default_qfr;
	} else {
		tgt->qfrs[UACCE_QFRT_SS] = src->qfrs[UACCE_QFRT_SS];
		list_add(&tgt->list, &src->qfrs[UACCE_QFRT_SS]->qs);
	}
	ret = 0;

out_with_fd:
	fput(filep);
	return ret;
}

static int uacce_start_queue(struct uacce_queue *q)
{
	struct device *dev = &q->uacce->dev;
	struct uacce_qfile_region *qfr;
	int ret, i, j;

	/*
	 * map KMAP qfr to kernel
	 * vmap should be done in non-spinlocked context!
	 */
	for (i = 0; i < UACCE_QFRT_MAX; i++) {
		qfr = q->qfrs[i];
		if (qfr && (qfr->flags & UACCE_QFRF_KMAP) && !qfr->kaddr) {
			qfr->kaddr = vmap(qfr->pages, qfr->nr_pages, VM_MAP,
					  PAGE_KERNEL);
			if (!qfr->kaddr) {
				ret = -ENOMEM;
				dev_err(dev, "fail to kmap %s qfr(%ld pages)\n",
					uacce_qfrt_str(qfr), qfr->nr_pages);
				goto err_with_vmap;
			}

			dev_dbg(dev, "kernel vmap %s qfr(%ld pages) to %pK\n",
				uacce_qfrt_str(qfr), qfr->nr_pages,
				qfr->kaddr);
		}
	}

	ret = q->uacce->ops->start_queue(q);
	if (ret < 0) {
		dev_err(dev, "uacce fails to start queue!\n");
		goto err_with_vmap;
	}

	dev_dbg(&q->uacce->dev, "uacce queue state switch to STARTED\n");
	q->state = UACCE_Q_STARTED;

	return 0;

err_with_vmap:
	for (j = i - 1; j >= 0; j--) {
		qfr = q->qfrs[j];
		if (qfr && qfr->kaddr) {
			vunmap(qfr->kaddr);
			qfr->kaddr = NULL;
		}
	}
	return ret;
}

static long uacce_get_ss_dma(struct uacce_queue *q, void __user *arg)
{
	struct uacce *uacce = q->uacce;
	struct uacce_dma_slice *slice;
	unsigned long slice_idx = 0;
	unsigned long dma, size;
	long ret = -EFAULT;

	if (!(uacce->flags & UACCE_DEV_NOIOMMU) || !q->qfrs[UACCE_QFRT_SS]) {
		dev_err(&uacce->dev, "no ss dma region!\n");
		return -EINVAL;
	}

	slice = q->qfrs[UACCE_QFRT_SS]->dma_list;
	if (copy_from_user(&slice_idx, arg, sizeof(unsigned long)))
		return ret;

	if (slice[0].total_num - 1 < slice_idx) {
		dev_err(&uacce->dev, "no ss slice idx %ld err!\n", slice_idx);
		return -EINVAL;
	}
	dma = slice[slice_idx].dma;
	size = slice[slice_idx].size;
	if (!dma || !size) {
		dev_err(&uacce->dev, "%ldth ss region no exist!\n", slice_idx);
		return -ENODEV;
	}
	dma = dma | (size >> UACCE_GRAN_SHIFT);
	if (copy_to_user(arg, &dma, sizeof(unsigned long)))
		return ret;

	return (long)(slice[0].total_num - 1 - slice_idx);
}

static long uacce_fops_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q;
	struct uacce *uacce;
	long ret = 0;

	uacce_qs_wlock();

	if (unlikely(!filep->private_data)) {
		uacce_qs_wunlock();
		return -EBADF;
	}
	q = filep->private_data;
	uacce = q->uacce;

	if (!uacce_q_avail_ioctl(q, cmd)) {
		uacce_qs_wunlock();
		return -EINVAL;
	}

	switch (cmd) {
	case UACCE_CMD_SHARE_SVAS:
		ret = uacce_cmd_share_qfr(q, (int)arg);
		break;
	case UACCE_CMD_START:
		ret = uacce_start_queue(q);
		break;
	case UACCE_CMD_GET_SS_DMA:
		ret = uacce_get_ss_dma(q, (void __user *)arg);
		break;
	case UACCE_CMD_PUT_Q:
		ret = uacce_put_queue(q);
		break;
	default:
		uacce_qs_wunlock();
		if (uacce->ops->ioctl)
			/* This is not protected by uacce_qs_lock */
			return uacce->ops->ioctl(q, cmd, arg);

		dev_err(&uacce->dev, "ioctl cmd (%d) is not supported!\n", cmd);
		return -EINVAL;
	}

	uacce_qs_wunlock();

	return ret;
}

#ifdef CONFIG_COMPAT
static long uacce_fops_compat_ioctl(struct file *filep,
				    unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return uacce_fops_unl_ioctl(filep, cmd, arg);
}
#endif

static int uacce_dev_open_check(struct uacce *uacce)
{
	if (uacce->flags & UACCE_DEV_NOIOMMU)
		return 0;

	/*
	 * The device can be opened once if it dose not support multiple page
	 * table. The better way to check this is counting it per iommu_domain,
	 * this is just a temporary solution
	 */
	if (uacce->flags & (UACCE_DEV_PASID | UACCE_DEV_NOIOMMU))
		return 0;

	if (!atomic_read(&uacce->ref))
		return 0;

	dev_info(&uacce->dev, "this device can be openned only once\n");
	return -EBUSY;
}

static int uacce_queue_drain(struct uacce_queue *q)
{
	struct uacce_qfile_region *qfr;
	bool is_to_free_region;
	struct uacce *uacce;
	int state;
	int i;

	uacce = q->uacce;

	state = (q->state == UACCE_Q_INIT || q->state == UACCE_Q_STARTED) ? 1 :
									    0;
	if (state && uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	for (i = 0; i < UACCE_QFRT_MAX; i++) {
		qfr = q->qfrs[i];
		if (!qfr)
			continue;

		is_to_free_region = false;
		uacce_queue_unmap_qfr(q, qfr);
		if (i == UACCE_QFRT_SS && !(qfr->flags & UACCE_QFRF_DMA)) {
			list_del(&q->list);
			if (list_empty(&qfr->qs))
				is_to_free_region = true;
		} else
			is_to_free_region = true;

		if (is_to_free_region)
			uacce_destroy_region(q, qfr);
	}
#ifdef CONFIG_IOMMU_SVA
	if (uacce->flags & UACCE_DEV_SVA)
		iommu_sva_unbind_device(uacce->pdev, q->pasid);
#endif
	if (state && uacce->ops->put_queue)
		uacce->ops->put_queue(q);

	/*
	 * Put_queue above just put hardware queue, but not free uacce_q.
	 *
	 * Put_queue(and stop_queue) is used to support UACCE_PUT_QUEUE
	 * ioctl, UACCE_PUT_QUEUE is defined only to put low level hardware
	 * queue, after UACCE_PUT_QUEUE ioctl, uacce_queue enters into zombie
	 * state. So uacce_queue can only be freed here.
	 */
	kfree(q);
	atomic_dec(&uacce->ref);

	return 0;
}

/*
 * While user space releases a queue, all the relatives on the queue
 * should be released imediately by this putting.
 */
static long uacce_put_queue(struct uacce_queue *q)
{
	struct uacce *uacce = q->uacce;

	/*
	 * To do: we should vm_munmap mmio and dus regions, currently we munmap
	 * mmio and dus region before put queue.
	 */
	if (uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);

	q->state = UACCE_Q_ZOMBIE;

	return 0;
}

static int uacce_get_queue(struct uacce *uacce, struct file *filep)
{
	struct uacce_queue *q;
	int ret;
	int pasid = 0;

#ifdef CONFIG_IOMMU_SVA
	if (uacce->flags & UACCE_DEV_PASID) {
		ret = iommu_sva_bind_device(uacce->pdev, current->mm, &pasid,
					    IOMMU_SVA_FEAT_IOPF, NULL);
		if (ret) {
			dev_err(uacce->pdev, "iommu SVA binds fail!\n");
			module_put(uacce->pdev->driver->owner);
			return ret;
		}
	}
#endif
	uacce_qs_wlock();

	ret = uacce->ops->get_queue(uacce, pasid, &q);
	if (ret < 0) {
		uacce_qs_wunlock();
		goto err_unbind;
	}
	q->pasid = pasid;
	q->uacce = uacce;
	q->mm = current->mm;
	memset(q->qfrs, 0, sizeof(q->qfrs));
	INIT_LIST_HEAD(&q->list);
	init_waitqueue_head(&q->wait);
	q->state = UACCE_Q_INIT;
	filep->private_data = q;
	atomic_inc(&uacce->ref);

	uacce_qs_wunlock();

	return 0;

err_unbind:
#ifdef CONFIG_IOMMU_SVA
	if (uacce->flags & UACCE_DEV_PASID)
		iommu_sva_unbind_device(uacce->pdev, pasid);
#endif
	module_put(uacce->pdev->driver->owner);
	return ret;
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce *uacce;
	int ret;

	uacce = idr_find(&uacce_idr, iminor(inode));
	if (!uacce) {
		pr_err("fail to find uacce device!\n");
		return -ENODEV;
	}

	if (!uacce->ops->get_queue) {
		dev_err(uacce->pdev, "uacce driver get_queue is NULL!\n");
		return -EINVAL;
	}

	if (!try_module_get(uacce->pdev->driver->owner)) {
		dev_err(uacce->pdev, "uacce try to get module(%s) fail!\n",
			uacce->pdev->driver->name);
		return -ENODEV;
	}
	ret = uacce_dev_open_check(uacce);
	if (ret) {
		module_put(uacce->pdev->driver->owner);
		return ret;
	}

	ret = uacce_get_queue(uacce, filep);
	if (ret) {
		dev_err(uacce->pdev, "uacce get queue fail!\n");
		return ret;
	}

	return 0;
}

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct uacce *uacce;
	int ret = 0;

	uacce_qs_wlock();

	q = filep->private_data;
	if (q) {
		uacce = q->uacce;
		/*
		 * As user space exception(without release queue), it will
		 * fall into this logic as the task exits to prevent hardware
		 * resources leaking.
		 */
		ret = uacce_queue_drain(q);
		filep->private_data = NULL;
	}

	uacce_qs_wunlock();

	if (q)
		module_put(uacce->pdev->driver->owner);

	return ret;
}

static enum uacce_qfrt uacce_get_region_type(struct uacce *uacce,
					     struct vm_area_struct *vma)
{
	enum uacce_qfrt type = UACCE_QFRT_MAX;
	size_t next_start = UACCE_QFR_NA;
	int i;

	for (i = UACCE_QFRT_MAX - 1; i >= 0; i--) {
		if (vma->vm_pgoff >= uacce->qf_pg_start[i]) {
			type = i;
			break;
		}
	}

	switch (type) {
	case UACCE_QFRT_MMIO:
		if (!uacce->ops->mmap) {
			dev_err(&uacce->dev, "no driver mmap!\n");
			return UACCE_QFRT_INVALID;
		}
		break;

	case UACCE_QFRT_DKO:
		if ((uacce->flags & UACCE_DEV_PASID) ||
		    (uacce->flags & UACCE_DEV_NOIOMMU)) {
			dev_err(&uacce->dev, "No DKO as device has PASID or no IOMMU!\n");
			return UACCE_QFRT_INVALID;
		}
		break;

	case UACCE_QFRT_DUS:
		break;

	case UACCE_QFRT_SS:

		/* todo: this can be valid to protect the process space */
		if (uacce->flags & UACCE_DEV_FAULT_FROM_DEV) {
			dev_err(&uacce->dev, "no SS in SVA mode!\n");
			return UACCE_QFRT_INVALID;
		}
		break;

	default:
		dev_err(&uacce->dev, "uacce invalid type(%d)!\n", type);
		return UACCE_QFRT_INVALID;
	}

	/* make sure the mapping size is exactly the same as the region */
	if (type < UACCE_QFRT_SS) {
		for (i = type + 1; i < UACCE_QFRT_MAX; i++)
			if (uacce->qf_pg_start[i] != UACCE_QFR_NA) {
				next_start = uacce->qf_pg_start[i];
				break;
			}

		if (next_start == UACCE_QFR_NA) {
			dev_err(&uacce->dev, "uacce config error. make sure setting SS offset properly\n");
			return UACCE_QFRT_INVALID;
		}

		if (vma_pages(vma) !=
		    next_start - uacce->qf_pg_start[type]) {
			dev_err(&uacce->dev, "invalid mmap size, (%ld vs %ld pages) for region %s.\n",
				vma_pages(vma),
				next_start - uacce->qf_pg_start[type],
				qfrt_str[type]);
			return UACCE_QFRT_INVALID;
		}
	}

	return type;
}





static ssize_t id_show(struct device *dev,
		       struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->dev_id);
}
static DEVICE_ATTR_RO(id);

static ssize_t qfrs_offset_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int i, ret;
	unsigned long offset;

	for (i = 0, ret = 0; i < UACCE_QFRT_MAX; i++) {
		offset = uacce->qf_pg_start[i];
		if (offset != UACCE_QFR_NA)
			offset = offset << PAGE_SHIFT;
		if (i == UACCE_QFRT_SS)
			break;
		ret += sprintf(buf + ret, "%lu\t", offset);
	}
	ret += sprintf(buf + ret, "%lu\n", offset);

	return ret;
}

static DEVICE_ATTR_RO(qfrs_offset);

static DEVICE_ATTR_RO(isolate);

static DEVICE_ATTR_RW(isolate_strategy);

static DEVICE_ATTR_RO(dev_state);


static const struct attribute_group uacce_dev_attr_group = {
	.name	= UACCE_DEV_ATTRS,
	.attrs	= uacce_dev_attrs,
};

static const struct attribute_group *uacce_dev_attr_groups[] = {
	&uacce_dev_attr_group,
	NULL
};

static void uacce_dev_release(struct device *dev) {}

static int uacce_create_chrdev(struct uacce *uacce)
{
	int ret;

	ret = idr_alloc(&uacce_idr, uacce, 0, 0, GFP_KERNEL);
	if (ret < 0)
		return ret;

	cdev_init(&uacce->cdev, &uacce_fops);
	uacce->dev_id = ret;
	uacce->cdev.owner = THIS_MODULE;
	device_initialize(&uacce->dev);
	uacce->dev.devt = MKDEV(MAJOR(uacce_devt), uacce->dev_id);
	uacce->dev.class = uacce_class;
	uacce->dev.groups = uacce_dev_attr_groups;
	uacce->dev.parent = uacce->pdev;
	uacce->dev.release = uacce_dev_release;
	dev_set_name(&uacce->dev, "%s-%d", uacce->drv_name, uacce->dev_id);
	ret = cdev_device_add(&uacce->cdev, &uacce->dev);
	if (ret)
		goto err_with_idr;

	dev_dbg(&uacce->dev, "create uacce minior=%d\n", uacce->dev_id);
	return 0;

err_with_idr:
	idr_remove(&uacce_idr, uacce->dev_id);
	return ret;
}

static void uacce_destroy_chrdev(struct uacce *uacce)
{
	cdev_device_del(&uacce->cdev, &uacce->dev);
	put_device(&uacce->dev);
	memset(&uacce->dev, 0, sizeof(struct device));
	idr_remove(&uacce_idr, uacce->dev_id);
}

static int uacce_default_get_available_instances(struct uacce *uacce)
{
	return -1;
}

static int uacce_default_start_queue(struct uacce_queue *q)
{
	dev_dbg(&q->uacce->dev, "fake start queue\n");
	return 0;
}

#ifndef CONFIG_IOMMU_SVA
static int uacce_dev_match(struct device *dev, void *data)
{
	if (dev->parent == data)
		return -EBUSY;

	return 0;
}

/* Borrowed from VFIO */
static bool uacce_iommu_has_sw_msi(struct iommu_group *group,
				   phys_addr_t *base)
{
	struct iommu_resv_region *region, *next;
	struct list_head group_resv_regions;
	bool ret = false;

	INIT_LIST_HEAD(&group_resv_regions);
	iommu_get_group_resv_regions(group, &group_resv_regions);
	list_for_each_entry(region, &group_resv_regions, list) {
		pr_debug("uacce: find a resv region (%d) on %llx\n",
			 region->type, region->start);

		/*
		 * The presence of any 'real' MSI regions should take
		 * precedence over the software-managed one if the
		 * IOMMU driver happens to advertise both types.
		 */
		if (region->type == IOMMU_RESV_MSI) {
			ret = false;
			break;
		}

		if (region->type == IOMMU_RESV_SW_MSI) {
			*base = region->start;
			ret = true;
		}
	}
	list_for_each_entry_safe(region, next, &group_resv_regions, list)
		kfree(region);
	return ret;
}

static int uacce_set_iommu_domain(struct uacce *uacce)
{
	struct device *dev = uacce->pdev;
	struct iommu_domain *domain;
	struct iommu_group *group;
	phys_addr_t resv_msi_base = 0;
	bool resv_msi;
	int ret;

	if (uacce->flags & UACCE_DEV_NOIOMMU)
		return 0;

	/*
	 * We don't support multiple register for the same dev in RFC version ,
	 * will add it in formal version
	 */
	ret = class_for_each_device(uacce_class, NULL, dev, uacce_dev_match);
	if (ret) {
		dev_err(dev, "no matching device in uacce class!\n");
		return ret;
	}

	/* allocate and attach a unmanged domain */
	domain = iommu_domain_alloc(dev->bus);
	if (!domain) {
		dev_err(dev, "fail to allocate domain on its bus\n");
		return -ENODEV;
	}

	ret = iommu_attach_device(domain, dev);
	if (ret) {
		dev_err(dev, "iommu attach device failing!\n");
		goto err_with_domain;
	}

	if (iommu_capable(dev->bus, IOMMU_CAP_CACHE_COHERENCY)) {
		uacce->prot |= IOMMU_CACHE;
		dev_dbg(dev, "Enable uacce with c-coherent capa\n");
	} else {
		dev_dbg(dev, "Enable uacce without c-coherent capa\n");
	}

	group = iommu_group_get(dev);
	if (!group) {
		dev_err(dev, "fail to get iommu group!\n");
		ret = -EINVAL;
		goto err_with_domain;
	}

	resv_msi = uacce_iommu_has_sw_msi(group, &resv_msi_base);
	iommu_group_put(group);

	if (resv_msi) {
		if (!irq_domain_check_msi_remap() &&
		    !iommu_capable(dev->bus, IOMMU_CAP_INTR_REMAP)) {
			dev_err(dev, "No interrupt remapping support!\n");
			ret = -EPERM;
			goto err_with_domain;
		}

		dev_dbg(dev, "Set resv msi %llx on iommu domain!\n",
			(u64)resv_msi_base);
		ret = iommu_get_msi_cookie(domain, resv_msi_base);
		if (ret) {
			dev_err(dev, "fail to get msi cookie from domain!\n");
			goto err_with_domain;
		}
	}

	return 0;

err_with_domain:
	iommu_domain_free(domain);
	return ret;
}

static void uacce_unset_iommu_domain(struct uacce *uacce)
{
	struct device *dev = uacce->pdev;
	struct iommu_domain *domain;

	if (uacce->flags & UACCE_DEV_NOIOMMU)
		return;

	domain = iommu_get_domain_for_dev(dev);
	if (domain) {
		iommu_detach_device(domain, dev);
		iommu_domain_free(domain);
	} else {
		dev_err(dev, "no domain attached to device\n");
	}
}
#endif

/**
 * uacce_register - register an accelerator
 * @uacce: the accelerator structure
 */
int uacce_register(struct uacce *uacce)
{
	struct device *dev = uacce->pdev;
	int ret;

	if (!dev) {
		pr_err("uacce parent device not set\n");
		return -ENODEV;
	}

	if (uacce->flags & UACCE_DEV_NOIOMMU) {
		add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);
		dev_warn(dev, "register to noiommu mode, it's not safe for kernel\n");
	}

	/* if dev support fault-from-dev, it should support pasid */
	if ((uacce->flags & UACCE_DEV_FAULT_FROM_DEV) &&
	    !(uacce->flags & UACCE_DEV_PASID)) {
		dev_err(dev, "SVM/SVA device should support PASID\n");
		return -EINVAL;
	}

	if (!uacce->ops) {
		dev_err(dev, "uacce ops is null\n");
		return -EINVAL;
	}

	if (!uacce->ops->start_queue)
		uacce->ops->start_queue = uacce_default_start_queue;

	if (!uacce->ops->get_available_instances)
		uacce->ops->get_available_instances =
			uacce_default_get_available_instances;

#ifndef CONFIG_IOMMU_SVA
	ret = uacce_set_iommu_domain(uacce);
	if (ret)
		return ret;
#endif

	ret = uacce_create_chrdev(uacce);
	if (ret) {
		dev_err(dev, "uacce creates cdev fail!\n");
		return ret;
	}

	if (uacce->flags & UACCE_DEV_PASID) {
#ifdef CONFIG_IOMMU_SVA
		ret = iommu_sva_init_device(uacce->pdev, IOMMU_SVA_FEAT_IOPF,
					    0, 0, NULL);
		if (ret) {
			dev_err(dev, "uacce sva init fail!\n");
			uacce_destroy_chrdev(uacce);
			return ret;
		}
#else
		uacce->flags &= ~(UACCE_DEV_FAULT_FROM_DEV | UACCE_DEV_PASID);
#endif
	}

	dev_dbg(&uacce->dev, "register to uacce!\n");
	atomic_set(&uacce->ref, 0);
	INIT_LIST_HEAD(&uacce->isolate_data.hw_errs);

	return 0;
}
EXPORT_SYMBOL_GPL(uacce_register);

/**
 * uacce_unregister - unregisters a uacce
 * @uacce: the accelerator to unregister
 *
 * Unregister an accelerator that wat previously successully registered with
 * uacce_register().
 */
int uacce_unregister(struct uacce *uacce)
{
	if (atomic_read(&uacce->ref) > 0) {
		printk_ratelimited("Fail to unregister uacce, please close all uacce queues!\n");
		return -EAGAIN;
	}

#ifdef CONFIG_IOMMU_SVA
	iommu_sva_shutdown_device(uacce->pdev);
#else
	uacce_unset_iommu_domain(uacce);
#endif
	uacce_hw_err_destroy(uacce);
	uacce_destroy_chrdev(uacce);

	return 0;
}
EXPORT_SYMBOL_GPL(uacce_unregister);

static int uacce_uevent(struct device *dev, struct kobj_uevent_env *env)
{
       add_uevent_var(env, "DEVMODE=%#o", 0666);
       return 0;
}

static int __init uacce_init(void)
{
	int ret;

	uacce_class = class_create(THIS_MODULE, UACCE_CLASS_NAME);
	if (IS_ERR(uacce_class)) {
		ret = PTR_ERR(uacce_class);
		goto err;
	}

        uacce_class->dev_uevent = uacce_uevent;
	ret = alloc_chrdev_region(&uacce_devt, 0, MINORMASK, "uacce");
	if (ret)
		goto err_with_class;

	pr_info("uacce init with major number:%d\n", MAJOR(uacce_devt));
	pr_debug("uacce debug enabled\n");

	return 0;

err_with_class:
	class_destroy(uacce_class);
err:
	return ret;
}

static __exit void uacce_exit(void)
{
	unregister_chrdev_region(uacce_devt, MINORMASK);
	class_destroy(uacce_class);
	idr_destroy(&uacce_idr);
}

subsys_initcall(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
MODULE_VERSION("1.1.10");

#include <linux/acpi.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/hw_random.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/random.h>
#include "../../include_uapi_linux/uacce.h"
#include "../../include_linux/uacce.h"
#include <crypto/internal/rng.h>

#define HISI_TRNG_REG 0x00F0
#define HISI_TRNG_BYTES 4
#define HISI_TRNG_QUALITY 512
#define HISI_TRNG_VERSION 0x01B8
#define HISI_TRNG_VER_V1 GENMASK(31,0)
#define SLEEP_US 10
#define TIMEOUT_US 10000
#define SW_DRBG_NUM_SHIFT 2
#define SW_DRBG_KEY_BASE 0x082C
#define SW_DRBG_SEED(n) (SW_DRBG_KEY_BASE - ((n) << SW_DRBG_NUM_SHIFT))
#define SW_DRBG_SEED_REGS_NUM 12
#define SW_DRBG_SEED_SIZW 48
#define MAX_QUEUE 1024
#define HISI_TRNG_PAGE_NR 1
#define SW_DRBG_CRYPTO_ALG_PRI 300
#define SW_DRBG_BLOCKS 0x0830
#define SW_DRBG_INIT 0x0834
#define SW_DRBG_GEN 0x083c
#define SW_DRBG_STATUS 0x0840
#define SW_DRBG_BLOCKS_NUM 4095
#define SW_DRBG_DARA_BASE 0x0850
#define SW_DRBG_DATA_NUM 4
#define SW_DRBG_DATA(n) (SW_DRBG_DATA_BASE - ((n) << SW_DRBG_NUM_SHIFT))
#define SW_DRBG_BYTES 16
#define SW_DRBG_ENABLE_SHIFT 12
#define SEED_SHITF_24 24
#define SEED_SHITF_16 16
#define SEED_SHITF_8 8

struct hisi_trng;
struct trng_queue{
    bool used;
    struct hisi_trng *trng;
    struct uacce_queue q;
};

struct hisi_trng_list{
    struct mutex lock;
    struct list_head list;
    bool is_init;
};

struct hisi_trng{
    voidd __iomen *base;
    struct hisi_trng_list *trng_list;
    struct list_headd list;
    struct hwrng rng;
    u32 drbg_used;
    u32 ver;
    bool is_used;

    resource_size_t base_pa;
    struct trng_queue qs[MAX_QUEUE];
    struct mutex mutex;
    struct uacce_device *uacce;
    u32 qp_used;
};

struct hisi_trng_ctx{
    struct hisi_trng *trng;
    struct cypto_rng *drbg;
};

static atomic_t trng_active_devs;
static struct hisi_trng_list trng_devices;

static void hisi_trng_set_seed(struct hisi_trng *trng, const u8 *seed){
    u32 val, seed_reg, i;

    for(i = 0; i < SW_DRBG_SEED_SIZE; i += SW_DRBG_SEED_SIZE / SW_DRBG_SEED_REGS_NUM){
        val = seed[i] << SEED_SHIFT_24;
        val |= seed[i + 1UL] << SEED_SHIFT_16;
        val |= seed[i + 2UL] << SEED_SHIFT_8;
        val |= seed[i + 3UL];

        seed_reg = (i >> SW_DRBG_NUM_SHIFT) % SW_DRBG_SEED_REGS_NUM;
        writel(val, trng->base + SW_DRBG_SEED(seed_reg));
    }
}

static int hisi_trng_seed(struct crypto_rng *tfm, const u8 *seed, unsigned int slen){
    struct hisi_trng_ctx *ctx = crypto_rng_ctx(tfm);
    struct crypto_rng *drbg = ctx->drbg;
    struct hisi_trng *trng =ctx->trng;
    u32 val = 0;
    int ret = 0;

    if(slen < SW_DRBG_SEED_SIZE){
        pr_err("slen(%u) is not matched with trng(%d)\n",slen,SW_DRBG_SEED_SIZE);
        return -EINVAL;
    }

    if(drbg){
        crypto_rng_set_entropy(drbg,seed,slen);
        return crypto_rng_reset(drbg,NULL,0);
    }

    writel(0x0, trng->base +SW_DRBG_BLOCKS);
    hisi_trng_set_seed(trng,seed);

    writel(SW_DRBG_BLOCKS_NUM | (0x1 << SW_DRBG_ENABLE_SHIFT), trng->base + SW_DRBG_BLOCKS);
    writel(0x1,trng->base + SW_DRBG_INIT);

    ret = readl_relaxed_poll_timeout(trng->base + SW_DRBG_STATUS, val, val & BIT(0), SLEEP_US, TIMEOUT_US);
    
    if(ret)
        pr_err("fail to init trng(%d)\n",ret);
    return ret;
}

static int hisi_trng_generate(struct crypto_rng *tfm, const u8 *src, unsigned int slen, u8 *dstn, unsigned int dlen){
    struct hisi_trng_ctx *ctx = crypto_rng_ctx(tfm);
    struct crypto_rng *drbg = ctx ->drbg;
    struct hisi_trng *trng = ctx->trng;
    u32 data[SW_DRBG_DATA_NUM];
    u32 currsize = 0;
    u32 val = 0;
    int ret;
    u32 i;

    if(drbg)
        return crypto_rng_generate(drbg,src,slen,dstn,dlen);
    
    do{
        ret = reeadl_relaxed_poll_timeout(trng->base + SW_DRBG_STATUS, val, val & BIT(1), SLEEP_US, TIMEOUT_US);
        if(ret){
            pr_err("fail to generate random number(%d)!\n",ret);
            break;
        }

        for(i=0;i<SW_DRBG_DATA_NUM;i++)
            data[i] = readl(trng->base + SW_DRBG_DATA(i));

        if(dlen - currsize >= SW_DRBG_BYTES){
            memcpy(dstn + currsize,data,SW_DRBG_BYTES);
            currsize += SW_DRBG_BYTES;
        } else{
            memcpy(dstn + currsize, data, dlen - currsize);
            currsize = dlen;
        }

        writel(0x1,trng->base +  SW_DRBG_GEN);
    } while(currsize < dlen);

    return ret;
}

static int hisi_trng_init(struct crypto_tfm *tfm){
    struct hisi_trng_ctx *ctx = crypto_tfm_ctx(tfm);
    struct hisi_trng *trng;
    int ret = 0;

    mutex_lock(&trng_devices.lock);
    list_for_each_entry(trng,&trng_devixes.list,list){
        if(!trng->is_used){
            trng->is_used = true;
            trng->drbg_uesd++l
            ctx->trng = trng;
            break;
        }
    }
    mutex_unlock(&trng_devices.lock);

    if(!ctx->trng){
        ctx->drbg = crypto_alloc_rng("drbg_nopr_ctr_aes256", 0, 0);
        if(IS_ERR(ctx->drbg)){
            pr_err("can not alloc rng!\n");
            ret = PTR_ERR(ctx->drbg);
            return ret;
        }

        mutex_lock(&trng_devices.lock);
        if(list_empty(&trng_devices.list)){
            mutex_unlock(&trng_devices.lock);
            crypto_free_rng(ctx->drbg);
            return -ENODEV;
        }
        trng = list_first_entry(&trng_devices.list, struct hisi_trng, list);
        trng -> drbg_used++;
        ctx->trng = trng;
        metex_unlock(&trng_devices.lock);
    }
    return ret;
}

static void hisi_trng_exit(struct crypto_tfm *tfm){
    struct hisi_trng_ctx *ctx = crypto_tfm_ctx(tfm);
    mutex_lock(&trng_devices.lock);
    if(!ctx->drbg)
        ctx->trng->is_used = false;
    else
        crypto_free_rng(ctx->drbg);
    ctx->trng->drbg_used--;
    mutex_unlock(&trng_devices.lock);
}

static init hisi_trng_read(struct hwrng *rng, void *buf, size_t max, book wait){
    struct hisi_trng *trng;
    int currsize = 0;
    u32 val = 0;
    int ret;
    
    trng = container_of(rng,struct hisi_trng,rng);
    do{
        ret = readl_poll_timeout(trng->base+HISI_TRNG_REG,val,val,SLEEP_US,TIMEOUT_US);
        if(ret)
            return currsize;
        if(max-currsize >= HISI_TRNG_BYTES){
            memcpy(buf +currsize, &val,HISI_TRNG_BYTES);
            currsize += HISI_TRNG_BYTES;
            if(currsize == max)
                return currsize;
            continue;
        }

        memcpy(buf + currsize, &val, max- currsize);
        currsize = max;
    }while (currsize < max);
    return currsize;
}

static int uacce_mode_set(const char *val,const struct kernel_param *kp){
    int ret;
    u32 n;

    if(val) return -EINVAL;
    ret = kstrtou32(val,10,&n);
    if(ret != 0 || (n != UACCE_MODE_NOIOMMU && n != UACCE_MODE_NOUACCE))
        return -EINVAL;
    return param_set_init(val,kp);
}

static const struct kernel_param_ops uacce_mode_ops ={
    .set = uacce_mode_set,
    .get = param_get_int,
};

static int uacce_mode = UACCE_MODE_NOUACCE;
module_param_cb(uacce_mode,&uacce_mode_ops.&uacce_mode,0444);
MODULE_PARAM_DESC(uacce_mode,"Mode of UACCE can be 0(default), 2");

static int hisi_trng_get_available_instances(struct uacce_device *uacce){
    struct hisi_trng *trng = uacce->priv;
    int i,ret;
    mutex_lock(&trng->mutex);
    for(i=0,ret=0;i<MAX_QUEUE;i++){
        if(!trng->qs[i].used)
            ret++;
    }
    mutex_unlock(&trng->mutex);
    return ret;
}

static int hisi_trng_get_queue(struct uacce_device *uacce, unsigned long arg, struct uacce_queue *q){
    struct hisi_trng *trng = uacce->priv;
    int i;
    mutex_lock(&trng->mutex);
    for(i = 0; i < MAX_QUEUE; i++){
        if(!trng->qs[i].used){
            trng->qa[i].used = true;
            trng->pq_used++;
            q->pric = &trng->qs[i];
            q->uacce = uacce;
            break;
        }
    }
    mutex_unlock(&trng->mutex);
    if(i < MAX_QUEUE)
        return 0;
    return -ENODEV;
}

static void hisi_trng_put_queue(struct uacce_queue *q){
    struct trng_queue *trng_queue = q->priv;
    struct hisi_trng *trng = trng_queue->trng;

    mutex_lock(&trng->mutex);
    trng_queue->used =false;
    trng->qp_used--;
    mutex_unlock(&trng->mutex);
}

static int hisi_trng_start_queue(struct uacce_queue *q)
{
    return 0;
}

static void hisi_trng_stop_queue(struct uacce_queue *q)
{

}

static int hisi_trng_mmap(struct uacce_queue *q,struct vm_area_struct *vma, struct uacce_qfile_region *qfr)
{
    struct trng_queue *trng_queue = q->priv;
    struct hisi_trng *trng = trng_queue -> trng;
    size_t sz = vma->vm_end - vma->vm_start;

    return remap_pfn_range(vma,vma->vm_start,trng->base_pa >> PAGE_SHIFT,sz,pgprot_noncached(vma->vm_page_prot));
    
};

static enum uacce_dev_state hisi_trng_get_state(struct uacce_device *uacce)
{
    return UACCE_DEV_NORMAL;
}

static int hisi_trng_frozen(struct hisi_trng *trng)
{
    int ret = -EBUSY;
    mutex_lock(&trng->mutex);
    if(!trng->qp_used){
        trng->qp_used = MAX_QUEUE;
        ret = 0;
    }
    metex_unlock(&trng->mutex);
    return ret;
}

static struct uscce_ops uacce_trng_ops = {
    .get_queue = hisi_trng_get_queue,
    .put_queue = hisi_trng_put_queue,
    .start_queue = hisi_trng_start_queue,
    .stop_queue = hisi_trng_stop_queue,
    .mmap = hisi_trng_mmap,
    .get_available_instances = hisi_trng_get_available_instances,
    .get_dev_state = hisi_trng_get_state,
};

static int trng_alloc_uacce(struct hisi_trng *trng, struct platform_device *pdev)
{
    struct uacce_interface interface;
    struct uacce_device *uacce;
    int name_len;

    name_len = strlen(pdev->dev.driver->name);
    if(name_len >= UACCCE_MAX_NAME_SIZE){
        dev_err(&pdev->dev,"The driver name(%d) is longer than %d!\n", name_len,UACCE_MAX_NAME_SIZE);
        return -EINVAL;
    }

    strncpy(interface.name, pdev->dev.driver->name,name_len);
    interface.name[name_len] = '\0';

    interface.flags = UACCE_DEV_NOIOMMU;
    interface.ops = &uacce_trng_ops;

    uacce = uacce_alloc(&pdev->dev,&interface);
    if(IS_ERR(uacce)) {
        dev_err(&pdev->dev,"fail to alloc uacce device\n!");
        return PTR_ERR(uacce);
    }

    uacce->qf_pg_num[UACCE_QFRT_MMIO] = HISI_TRNG_PAGE_NR;
    uacce->qf_pg_num[UACCE_QFRT_DUS] = UACCE_QFA_NA;
    uacce->isolate = &uacce->isolate_data;
    uacce->api_ver = "hisi-trng-v2";
    uacce->algs = "trng";
    uacce->priv = trng;
    uscce_is_vf = false;
    trng->uacce = uacce;

    return 0;
}


static int trng_register_uacce(struct hisi_trng *trng, struct platform_device *pdev)
{
    struct resource *res;
    int i, ret;

    if(uacce_mode != UACCE_MODE_NOIOMMU)
        return 0;
    res = platform_get_resource(pdev,IORESOURCE_MEN,0);
    if (!res)
    {
        dev_err(&pdev->dev,"failed to get resource\n");
        return -ENOMEN;
    }
    trng->base_pa = res->start;
    for(i = 0; i < MAX_QUEUE; i++) {
        trng->qs[i].trng = trng;
        trng->qs[i].q.priv = &trng->qs[i];
    }

    mutex_init(&trng->mutex);
    trng->qp_used = 0;
    ret = trng_alloc_uacce(trng,pdev);
    if(ret)
        return ret;
    dev_info(&pdev->dev,"trng register to uacce\n");
    ret = uacce_register(trng->uadcce);
    if(ret)
        uacce_remove(trng->uacce);

    return ret;
}

static struct rng_alf hisi_trng_alg = {
    .generate = hisi_trng_generate,
    .seed = hisi_trng_stop_seed,
    .seedsize = SW_DEBG_SEED_SIZE,
    .base = {
        .cra_name = "stdrng",
        .cra_driver_name = "hisi_stdrng",
        .cra_priority = SW_DRBG_CRYPTO_ALG_PRI,
        .cra_ctxsize = sizeof(struct hisi_trng_ctx),
        .cra_module =THIS_MODULE,
        .cra_init = hisi_trng_init,
        .cra_exit = hisi_trng_exit,
    },
};

static void hisi_trng_add_to_list(struct hisi_trng *trng)
{
    metex_lock(&trng_devices.lock);
    list_add_tail(&trng->list, &trng_devices.list);
    metex_unlock(&trng_devices.lock);
}

static int hisi_trng_del_from_list(truct hisi_trng *trng)
{
    int ret = -EBUSY;

    metex_lock(&trng_devices.lock);
    if (!trng->drbg_used)
    {
        list_del(&trng->list);
        ret = 0;
    }
    
    metex_unlock(&trng_devices.lock);
    return ret;
}

static int hisi_trng_probe(struct platform_device *pdev)
{
    struct hisi_trng *trng;
    int ret;

    trng = devm_kzalloc(&pdev->dev, sizeof(*trng), GFP_KERNEL);
    if (!trng)
    {
        return -ENOMEM;
    }
    
    platform_set_drvdata(pdev, trng);
    trng->base = devm_platform_ioremap_resource(pdev,0);
    if(IS_ERR(trng->base))
        return PTR_ERR(trng->base);

    trng->is_used = false;
    trng->drbg_used = 0; = false;
    trng->ver = readl(trng->base + HISI_TRNG_VERSION);
    if (!trng_devices.is_init) {
        INIT_LIST_HEAD(&trng_devices.list);
        mutex_init(&trng_devices.lock);
        trng_devices.is_init = true;
    }

    hisi_trng_add_to_list(trng);
    if (trng->ver != HISI_TRNG_VER_V1 &&
        atomic_inc_return(&trng_active_devs) == 1) {
        ret = crypto_register_rng(&hisi_trng_alg);
        if (ret) {
            dev_err(&pdev->dev,
                "failed to register crypto(%d)\n", ret);
            (void)atomic_dec_return(&trng_active_devs);
            goto err_remove_from_list;
        }
    }

    trng->rng.name = pdev->name;
    trng->rng.read = hisi_trng_read;
    trng->rng.quality = HISI_TRNG_QUALITY;
    ret = devm_hwrng_regiuster(&pdev->dev, &trng->rng);
    if (ret) {
        dev_err(&pdev->dev, "failed to register hwrng: %d!\n", ret);
        goto err_crypto_unregister;
    }

    ret = trng_register_uacce(trng, pdev);
    if (ret) {
        dev_err(&pdev->dev, "failed to register uacce: %d!\n", ret);
        goto err_crypto_unregister;
    }

    return ret;

err_crypto_unregister:
    if (trng->ver != HISI_TRNG_VER_V1 &&
        atomic_dec_return(&trng_active_devs) == 0)
        crypto_unregister_rng(&hisi_trng_alg);

err_remove_from_list:
    hisi_trng_del_from_list(trng);
    return ret;
}

static int hisi_trng_remove(struct platform_device *pdev)
{
    struct hisi_trng *trng = platform_get_drvdata(pdev);

    while (hisi_trng_del_from_list(trng))
        ;
    
    if (trng->ver != HISI_TRNG_VER_V1 &&
        atomic_dec_return(&trng_active_devs) == 0)
        crypto_unregister_rng(&hisi_trng_alg);
    
    if (uacce_mode == UACCE_MODE_NOIOMMU) {
        while (hisi_trng_frozen(trng))
            ;
        
        uacce_remove(trng->uacce);
    }

    return 0;
}

static const struct acpi_device_id hisi_trng_acpi_match[] = {
    { "HISI02B3", 0 },
    { }
};
MODULE_DEVICE_TABLE(acpi, hisi_trng_acpi_match);

static struct platform_driver hisi_trng_driver = {
    .probe = hisi_trng_probe,
    .remove = hisi_trng_remove,
    .driver = {
        .name = "hisi-trng-v2",
        .acpi_match_table = ACPI_PTR(hisi_trng_acpi_match),
    },
};

module_platform_driver(hisi_trng_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Weili Qian <qianweili@huawei.com>");
MODULE_AUTHOR("Zaibo Xu <xuzaibo@huawei.com>");
MODULE_DESCRIPTION("HiSilicon true random number generator V2 driver");
// SPDX-License-Identifier: GPL-2.0-only

#include <linux/stddef.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/list.h>
#include <asm/topology.h>
#include <linux/cpumask.h>

#define HYBRID_SHM_NAME "hybrid_shm"

struct hybrid_shm_pcie {
	struct pci_dev *pci;
	void __iomem *mmio;
};

static struct hybrid_shm_pcie hybrid_shm;

static const struct pci_device_id hybrid_shm_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1110), 0 },
	{ 0 }
};

static int get_perf_value(void *__iomem start)
{
	int cpu;
	int perf;

	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		perf = (int)ioread8(start + cpu);
		sched_set_itmt_core_prio(perf, cpu);
                dev_err(&hybrid_shm.pci->dev, "cpu %d, perf %d\n", cpu, perf);
	}

	return sched_set_itmt_support();
}

static int hybrid_shm_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{
	int rc = 0;

	hybrid_shm.pci = pdev;
	pci_set_drvdata(pdev, &hybrid_shm);

	rc = pci_enable_device_mem(pdev);
	if (rc) {
		dev_err(&pdev->dev, "failed to enable pci device\n");
		goto error_exit;
	}

	rc = pci_request_regions(pdev, HYBRID_SHM_NAME);
	if (rc) {
		dev_err(&pdev->dev, "failed to request mmio regions\n");
		goto error_req_mem;
	}

	hybrid_shm.mmio = pci_ioremap_bar(pdev, 2);
	if (!hybrid_shm.mmio) {
		dev_err(&pdev->dev, "failed to ioremap BAR2\n");
		goto error_map;
	}

	rc = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (rc) {
		dev_err(&pdev->dev, "failed to set dma mask\n");
		goto error_dma_mask;
	}

	pci_set_master(pdev);

        if (!get_perf_value(hybrid_shm.mmio))
            dev_info(&pdev->dev, "hybrid_shm inited\n");
        else
            dev_err(&pdev->dev, "hybrid_shm failed to set perf data\n");

	return 0;

error_dma_mask:
	if (hybrid_shm.mmio)
		iounmap(hybrid_shm.mmio);
error_map:
	pci_release_regions(pdev);
error_req_mem:
	pci_disable_device(pdev);
error_exit:
	pci_set_drvdata(pdev, NULL);
	memset(&hybrid_shm, 0, sizeof(struct hybrid_shm_pcie));

	return rc;
}

static void hybrid_shm_remove(struct pci_dev *pdev)
{
	if (hybrid_shm.mmio)
		iounmap(hybrid_shm.mmio);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_driver hybrid_shm_driver = { .name = "hybrid_shm",
					       .id_table = hybrid_shm_id_table,
					       .probe = hybrid_shm_probe,
					       .remove = hybrid_shm_remove };

static int __init hybrid_shm_init_module(void)
{
	return pci_register_driver(&hybrid_shm_driver);
}

static void __exit hybrid_shm_exit_module(void)
{
	pci_unregister_driver(&hybrid_shm_driver);
}

module_init(hybrid_shm_init_module);
module_exit(hybrid_shm_exit_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xin Zhang <zhangxin.xa@gmail.com>");
MODULE_DESCRIPTION(
	"KVM ivshmem driver for sharing hybrid CPU per core perf value");
MODULE_VERSION("0.1");

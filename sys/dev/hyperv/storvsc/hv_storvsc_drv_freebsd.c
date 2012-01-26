#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>
#include <sys/bus.h>
#include <sys/mutex.h>
#include <vm/vm.h>
#include <vm/pmap.h>

#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/cam_periph.h>
#include <cam/cam_sim.h>
#include <cam/cam_xpt_sim.h>
#include <cam/cam_xpt_internal.h>
#include <cam/cam_debug.h>
#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_message.h>

#include <hv_osd.h>
#include <hv_vmbus_var.h>
#include <hv_vmbus_api.h>
#include <hv_vmbus.h>
#include <hv_logging.h>

#include "hv_stor_vsc_api.h"


struct storvsc_driver_context {
	/*
	 * These must be the first two fields
	 */
	struct driver_context    drv_ctx;
	STORVSC_DRIVER_OBJECT    drv_obj;
	const char		*drv_name;
	uint8_t			 drv_max_luns_per_target;
	uint8_t			 drv_max_ios_per_target;
	uint32_t		 drv_inited;
};

struct storvsc_softc {
	DEVICE_OBJECT *storvsc_dev;
	struct storvsc_driver_context *sto_drv;
	int unit;
	struct cam_sim *sim;
	struct cam_path *path;
	LIST_HEAD(, storvsc_request) free_list;
	struct mtx free_list_lock;
};


// The one and only one
/* SCSI HBA */
static struct storvsc_driver_context g_storvsc_drv;
/* IDE HBA  */
static struct storvsc_driver_context g_blkvsc_drv;

/* static functions */
static int storvsc_probe(device_t dev);
static int storvsc_attach(device_t dev);
static void storvsc_init(void);
static int storvsc_detach(device_t dev);
static int storvsc_drv_init(struct storvsc_driver_context *vsc_drv,
			    PFN_DRIVERINITIALIZE pfn_drv_init);
static void storvsc_poll(struct cam_sim * sim);
static void storvsc_action(struct cam_sim * sim, union ccb * ccb);
static void scan_for_luns(struct storvsc_softc * storvsc_softc);
static void create_storvsc_request(union ccb *ccb, struct storvsc_request *reqp);
static void storvsc_free_request(struct storvsc_softc *sc, struct storvsc_request *reqp);
static struct storvsc_driver_context *storvsc_get_storage_type(device_t dev);
static void storvsc_io_completion(struct storvsc_request *reqp);

static device_method_t storvsc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		storvsc_probe),
	DEVMETHOD(device_attach,	storvsc_attach),
	DEVMETHOD(device_detach,	storvsc_detach),
	DEVMETHOD(device_shutdown,      bus_generic_shutdown),
	{ 0, 0 }
};

static driver_t storvsc_driver = {
	"storvsc", storvsc_methods, sizeof(struct storvsc_softc),
};

static devclass_t storvsc_devclass;
DRIVER_MODULE(storvsc, vmbus, storvsc_driver, storvsc_devclass, 0, 0);
MODULE_VERSION(storvsc,1);
MODULE_DEPEND(storvsc, vmbus, 1, 1, 1);
// TODO: We want to be earlier than SI_SUB_VFS
SYSINIT(storvsc_initx, SI_SUB_VFS, SI_ORDER_MIDDLE + 1, storvsc_init, NULL);

static void
storvsc_xptdone(struct cam_periph *periph, union ccb *done_ccb)
{
	wakeup(&done_ccb->ccb_h.cbfcnp);
}
static void
storvsc_xptscandone(struct cam_periph *periph, union ccb *request_ccb)
{
	struct storvsc_softc *storvsc_softc;
	struct cam_path	     *new_path;
	int		      lun_nb;
	int		      status;

	storvsc_softc = request_ccb->ccb_h.sim_priv.entries[0].ptr;

	new_path      = request_ccb->ccb_h.path;
	lun_nb	      = request_ccb->ccb_h.sim_priv.entries[1].field;

	//xpt_print(new_path, "LUN %d scan 0x%p On this controller\n", lun_nb, new_path);
	xpt_release_path(new_path);
	if (++lun_nb < storvsc_softc->sto_drv->drv_max_luns_per_target) {
	
		/*
		 * Scan the next LUN. Reuse path and ccb structs.
		 */
		bzero(new_path, sizeof(*new_path));
		bzero(request_ccb, sizeof(*request_ccb));
		status = xpt_compile_path(new_path,
                                          xpt_periph,
                                          storvsc_softc->path->bus->path_id,
                                          0,
                                          lun_nb);

                if (status != CAM_REQ_CMP) {
                        xpt_print(storvsc_softc->path, "scan_for_luns: can't compile path, 0x%p "
                                          "can't continue\n", storvsc_softc->path);
                        free(request_ccb, M_CAMXPT);
                        free(new_path, M_CAMXPT);
                        return;
                }
		xpt_setup_ccb(&request_ccb->ccb_h, new_path, 5);
		request_ccb->ccb_h.func_code		     = XPT_SCAN_LUN;
		request_ccb->ccb_h.cbfcnp		     = storvsc_xptscandone;
		request_ccb->crcn.flags			     = CAM_FLAG_NONE;
		request_ccb->ccb_h.sim_priv.entries[0].ptr   = storvsc_softc;
		request_ccb->ccb_h.sim_priv.entries[1].field = lun_nb;

		xpt_action(request_ccb);
		
	} else {
		/*
		 * Done scanning for LUNs
		 */	
		free(new_path, M_CAMXPT);
		free(request_ccb, M_CAMXPT);
	}

}

/**
 * scan_for_luns
 *
 * In Hyper-V there is no backend changed device operation which
 * presents FreeBSD with a list of devices to connect.  The result is
 * that we have to scan for a list of luns in the storvsc_attach()
 * routine.  There is only one SCSI target, so scan for the maximum
 * number of luns.
 */
static void
scan_for_luns(struct storvsc_softc *storvsc_softc)
{
	union ccb *request_ccb;
	struct cam_path *path = storvsc_softc->path;
	struct cam_path *new_path = NULL;
	cam_status status;
	int lun_nb = 0;

	request_ccb = malloc(sizeof(union ccb), M_CAMXPT, M_NOWAIT | M_ZERO);
	if (request_ccb == NULL) {
                xpt_print(path, "scan_for_lunsX: can't compile path, 0x%p "
                                         "can't continue\n", storvsc_softc->path);
		return;
	}
	new_path = malloc(sizeof(*new_path), M_CAMXPT, M_NOWAIT | M_ZERO);
	if (new_path == NULL) {
		xpt_print(path, "scan_for_luns: can't allocate path, "
				  "can't continue\n");
		free(request_ccb, M_CAMXPT);
		return;
	}
	status = xpt_compile_path(new_path,
				  xpt_periph,
				  path->bus->path_id,
				  0,
				  lun_nb);

	if (status != CAM_REQ_CMP) {
                xpt_print(path, "scan_for_lunYYY: can't compile path, 0x%p "
                                         "can't continue\n", storvsc_softc->path);
		free(request_ccb, M_CAMXPT);
		free(new_path, M_CAMXPT);
		return;
	}

	//xpt_print(new_path, "New %d scan 0x%p \n", lun_nb, new_path);
	xpt_setup_ccb(&request_ccb->ccb_h, new_path, 5);
	request_ccb->ccb_h.func_code		     = XPT_SCAN_LUN;
	request_ccb->ccb_h.cbfcnp		     = storvsc_xptdone;
	request_ccb->crcn.flags			     = CAM_FLAG_NONE;
	request_ccb->ccb_h.sim_priv.entries[0].ptr   = storvsc_softc;
	request_ccb->ccb_h.sim_priv.entries[1].field = lun_nb;

	xpt_action(request_ccb);
	/*
	 * Wait for LUN 0 to configure. This is to synchronize mountroot on IDE controllers.
         * They only have LUN 0
	 */
	cam_periph_ccbwait(request_ccb);

	/*
	 * Kick of next LUN
	 */
	storvsc_xptscandone(request_ccb->ccb_h.path->periph, request_ccb);
}

static int
storvsc_probe(device_t dev)
{
	int ret       = ENXIO;

	/* 
	 * If the system has already booted and thread
	 * scheduling is possible indicated by the global
	 * cold set to zero, we just call the driver
	 * initialization directly.
	 */
	if (!cold && 
	    (!g_storvsc_drv.drv_inited || !g_blkvsc_drv.drv_inited)) {
		storvsc_init();
	}

	if (storvsc_get_storage_type(dev) != NULL) {
		ret = 0;;
	} else {
		printf("Storvsc probe 0x%p ...FAILED\n", dev);
	}
	return (ret);
}

static void
storvsc_init(void)
{
	DPRINT_ENTER(STORVSC_DRV);

	/*
	 * SCSI adapters.
	 */
	if (g_storvsc_drv.drv_inited == 0) {
		g_storvsc_drv.drv_name		      = "storvsc";
		g_storvsc_drv.drv_max_luns_per_target = STORVSC_MAX_LUNS_PER_TARGET;
		g_storvsc_drv.drv_max_ios_per_target  = STORVSC_MAX_IO_REQUESTS;
		storvsc_drv_init(&g_storvsc_drv, StorVscInitialize);
		atomic_set_int(&g_storvsc_drv.drv_inited,1);
	}

	/*
	 * Hyper-v IDE devices are accessed as SCSI devices with a different GUID.
	 */
	if (g_blkvsc_drv.drv_inited == 0) {
		g_blkvsc_drv.drv_name		      = "blkvsc";
		g_blkvsc_drv.drv_max_luns_per_target = BLKVSC_MAX_IDE_DISKS_PER_TARGET;
		g_blkvsc_drv.drv_max_ios_per_target  = BLKVSC_MAX_IO_REQUESTS;
		storvsc_drv_init(&g_blkvsc_drv, BlkVscInitialize);
		atomic_set_int(&g_blkvsc_drv.drv_inited,1);
	}

	DPRINT_EXIT(STORVSC_DRV);
}

/*++

Name:   storvsc_drv_init()

Desc:   StorVsc driver initialization

--*/
static int
storvsc_drv_init(struct storvsc_driver_context *vsc_drv,
		 PFN_DRIVERINITIALIZE pfn_drv_init)
{
	int ret=0;
	STORVSC_DRIVER_OBJECT *stor_drv_obj=&vsc_drv->drv_obj;
	struct driver_context *drv_ctx=&vsc_drv->drv_ctx;

	DPRINT_ENTER(STORVSC_DRV);

	vmbus_get_interface(&stor_drv_obj->Base.VmbusChannelInterface);

	stor_drv_obj->RingBufferSize = STORVSC_RINGBUFFER_SIZE;

	// Callback to client driver to complete the initialization
	pfn_drv_init(&stor_drv_obj->Base);

	memcpy(&drv_ctx->class_id, &stor_drv_obj->Base.deviceType, sizeof(GUID));

	// The driver belongs to vmbus
	vmbus_child_driver_register(drv_ctx);

	DPRINT_EXIT(STORVSC_DRV);

	return ret;
}

static int
storvsc_attach(device_t dev)
{
	struct storvsc_driver_context *storvsc_drv;
	STORVSC_DRIVER_OBJECT *storvsc_drv_obj;
	struct device_context *device_ctx = vmbus_get_devctx(dev);

	STORVSC_DEVICE_INFO device_info;
	struct storvsc_softc *sc;
	struct cam_devq *devq;
	int ret, i;
	struct storvsc_request *reqp;

	DPRINT_ENTER(STORVSC_DRV);

	sc = device_get_softc(dev);
	if (sc == NULL) {
		DPRINT_ERR(STORVSC_DRV, "softc not configured");
		ret = ENOMEM;
		return ret;
	}

	storvsc_drv = storvsc_get_storage_type(dev);
	if (storvsc_drv == NULL) {
		DPRINT_ERR(STORVSC_DRV, "Not a storvsc_device");
		return (-1);
	}

	storvsc_drv_obj = &storvsc_drv->drv_obj;

	if (!storvsc_drv_obj->Base.OnDeviceAdd) {
		DPRINT_ERR(STORVSC_DRV, "OnDeviceAdd is not initialized");
		return -1;
	}

	bzero(sc, sizeof(struct storvsc_softc));
	device_ctx->device_obj.Driver = &storvsc_drv_obj->Base;

	sc->sto_drv	= storvsc_drv;
	sc->unit	= device_get_unit(dev);
	sc->storvsc_dev = &device_ctx->device_obj;

	LIST_INIT(&sc->free_list);
	mtx_init(&sc->free_list_lock, "storvsc free list lock", NULL, MTX_SPIN | MTX_RECURSE);

	for (i = 0; i < sc->sto_drv->drv_max_ios_per_target; ++i) {
		reqp = malloc(sizeof(struct storvsc_request), M_DEVBUF, M_NOWAIT | M_ZERO);
		if (reqp == NULL) {
			printf("cannot alloc struct storvsc_request\n");
			goto cleanup;
		}

		reqp->Softc = sc;
		reqp->Extension = malloc(storvsc_drv_obj->RequestExtSize, M_DEVBUF, M_NOWAIT | M_ZERO);
		if (reqp->Extension == NULL) {
			printf("cannot alloc request extension\n");
			goto cleanup;
		}

		LIST_INSERT_HEAD(&sc->free_list, reqp, link);
	}

	ret = storvsc_drv_obj->Base.OnDeviceAdd(&device_ctx->device_obj, (void*)&device_info);

	if (ret != 0) {
		DPRINT_ERR(STORVSC_DRV, "unable to add storvsc device (ret %d)", ret);
		
		return ret;
	}

	// Create the device queue.
	// Hyper-V maps each target to one SCSI HBA
	devq = cam_simq_alloc(sc->sto_drv->drv_max_ios_per_target);
	if (devq == NULL) {
		printf("Failed to alloc device queue\n");
		return (ENOMEM);
	}

	// XXX avoid Giant?
	sc->sim = cam_sim_alloc(storvsc_action,
				storvsc_poll,
				sc->sto_drv->drv_name,
				sc,
				sc->unit,
				&Giant, 1,
				sc->sto_drv->drv_max_ios_per_target,
				devq);

	if (sc->sim == NULL) {
		printf("Failed to alloc sim\n");
		cam_simq_free(devq);
		return (ENOMEM);
	}

	if (xpt_bus_register(sc->sim, dev, 0) != CAM_SUCCESS) {
		cam_sim_free(sc->sim, /*free_devq*/TRUE);
		printf("Unable to register SCSI bus\n");
		return (ENXIO);
	}

	if (xpt_create_path(&sc->path, /*periph*/NULL, cam_sim_path(sc->sim),
						CAM_TARGET_WILDCARD, CAM_LUN_WILDCARD) != CAM_REQ_CMP) {
		xpt_bus_deregister(cam_sim_path(sc->sim));
		cam_sim_free(sc->sim, /*free_devq*/TRUE);
		printf("Unable to create path\n");
		return (ENXIO);
	}

	scan_for_luns(sc);
	DPRINT_EXIT(STORVSC_DRV);
	return 0;

 cleanup:

	while (!LIST_EMPTY(&sc->free_list)) {
		reqp = LIST_FIRST(&sc->free_list);
		LIST_REMOVE(reqp, link);

		if (reqp->Extension) {
			free(reqp->Extension, M_DEVBUF);
		}
		free(reqp, M_DEVBUF);
	}
	return -1;
}
static int storvsc_detach(device_t dev)
{
	struct storvsc_softc *sc = device_get_softc(dev);
	struct storvsc_request *reqp = NULL;

	mtx_lock(&sc->free_list_lock);
	while (!LIST_EMPTY(&sc->free_list)) {
		reqp = LIST_FIRST(&sc->free_list);
		LIST_REMOVE(reqp, link);

		if (reqp->Extension) {
			free(reqp->Extension, M_DEVBUF);
		}
		free(reqp, M_DEVBUF);
	}
	mtx_unlock(&sc->free_list_lock);
	return 0;
}

static void storvsc_poll(struct cam_sim *sim)
{
}

static void storvsc_action(struct cam_sim *sim, union ccb *ccb)
{
	struct storvsc_softc *sc = cam_sim_softc(sim);
	struct storvsc_driver_context *sto_drv = sc->sto_drv;
	STORVSC_DRIVER_OBJECT *stor_drv_obj = &sto_drv->drv_obj;
	int res;

    switch (ccb->ccb_h.func_code) {
	case XPT_PATH_INQ: {
		struct ccb_pathinq *cpi = &ccb->cpi;
		DPRINT_INFO(STORVSC, "XPT_PATH_INQ %d:%d:%d %s\n", cam_sim_bus(sim),
					ccb->ccb_h.target_id, ccb->ccb_h.target_lun, cam_sim_name(sim));

		cpi->version_num = 1;
		cpi->hba_inquiry = PI_TAG_ABLE|PI_SDTR_ABLE;
		cpi->target_sprt = 0;
		cpi->hba_misc = PIM_NOBUSRESET;
		cpi->hba_eng_cnt = 0;
		cpi->max_target = STORVSC_MAX_TARGETS;
		cpi->max_lun = sto_drv->drv_max_luns_per_target;
		cpi->initiator_id = 0;
		cpi->bus_id = cam_sim_bus(sim);
		cpi->base_transfer_speed = 300000;
		cpi->transport = XPORT_SAS;
		cpi->transport_version = 0;
		cpi->protocol = PROTO_SCSI;
		cpi->protocol_version = SCSI_REV_SPC2;
		strncpy(cpi->sim_vid, "FreeBSD", SIM_IDLEN);
		strncpy(cpi->hba_vid, sto_drv->drv_name, HBA_IDLEN);
		strncpy(cpi->dev_name, cam_sim_name(sim), DEV_IDLEN);
		cpi->unit_number = cam_sim_unit(sim);

		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		return;
	}
	case XPT_GET_TRAN_SETTINGS: {
		struct  ccb_trans_settings *cts = &ccb->cts;

		cts->transport = XPORT_SAS;
		cts->transport_version = 0;
		cts->protocol = PROTO_SCSI;
		cts->protocol_version = SCSI_REV_SPC2;

		// Enable tag queuing and disconnected mode
		cts->proto_specific.valid = CTS_SCSI_VALID_TQ;
		cts->proto_specific.scsi.valid = CTS_SCSI_VALID_TQ;
		cts->proto_specific.scsi.flags = CTS_SCSI_FLAGS_TAG_ENB;
		cts->xport_specific.valid = CTS_SPI_VALID_DISC;
		cts->xport_specific.spi.flags = CTS_SPI_FLAGS_DISC_ENB;
			
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		return;
	}
	case XPT_SET_TRAN_SETTINGS:	{
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		return;
	}
	case XPT_CALC_GEOMETRY:{
		cam_calc_geometry(&ccb->ccg, 1);
		xpt_done(ccb);
		return;
	}
	case  XPT_RESET_BUS:
	case  XPT_RESET_DEV:{
#ifdef notyet
		if ((res = stor_drv_obj->OnHostReset(sc->storvsc_dev)) != 0) {
			printf("OnHostReset failed with %d\n", res);
			ccb->ccb_h.status = CAM_PROVIDE_FAIL;
			xpt_done(ccb);
			return;
		}
#endif	 /* notyet */
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		return;
	}
	case XPT_SCSI_IO:
	case XPT_IMMED_NOTIFY: {
		struct storvsc_request *reqp = NULL;

		if (ccb->csio.cdb_len == 0) {
			panic("cdl_len is 0\n");
		}

		mtx_lock(&sc->free_list_lock);
		if (LIST_EMPTY(&sc->free_list)) {
			mtx_unlock(&sc->free_list_lock);
			printf("no free requests\n");
			ccb->ccb_h.status = CAM_RESRC_UNAVAIL;
			xpt_done(ccb);
			return;
		}

		reqp = LIST_FIRST(&sc->free_list);
		LIST_REMOVE(reqp, link);
		mtx_unlock(&sc->free_list_lock);
		ASSERT(reqp);

		ccb->ccb_h.status = CAM_SIM_QUEUED;	    

		create_storvsc_request(ccb, reqp);
		if ((res = stor_drv_obj->OnIORequest(sc->storvsc_dev, reqp)) == -1) {
			printf("OnIORequest failed with %d\n", res);
			ccb->ccb_h.status = CAM_PROVIDE_FAIL;
			storvsc_free_request(sc, reqp);
			xpt_done(ccb);
			return;
		}
		return;
	}

	default:
		ccb->ccb_h.status = CAM_REQ_INVALID;
		xpt_done(ccb);
		return;
	}
}

static void
create_storvsc_request(union ccb *ccb, struct storvsc_request *reqp)
{
	struct ccb_scsiio *csio = &ccb->csio;
	uint64_t phys_addr;
	uint32_t bytes_to_copy = 0;
	uint32_t pfn_num = 0;
	uint32_t pfn;
	
	reqp->Host = cam_sim_unit(xpt_path_sim(ccb->ccb_h.path));
	reqp->TargetId = ccb->ccb_h.target_id;
	reqp->PathId = reqp->Bus = ccb->ccb_h.path_id;
	reqp->LunId = ccb->ccb_h.target_lun;

	reqp->CdbLen = csio->cdb_len;
	if(ccb->ccb_h.flags & CAM_CDB_POINTER) {
		memcpy(reqp->Cdb, csio->cdb_io.cdb_ptr, reqp->CdbLen);
	} else {
		memcpy(reqp->Cdb, csio->cdb_io.cdb_bytes, reqp->CdbLen);
	}

	switch (ccb->ccb_h.flags & CAM_DIR_MASK) {
    	case CAM_DIR_OUT: 
    		reqp->Type = WRITE_TYPE;
    		break;
    	case CAM_DIR_IN:
    		reqp->Type = READ_TYPE;
    		break;
    	case CAM_DIR_NONE:
    		reqp->Type = UNKNOWN_TYPE;
    		break;
    	default:
    		reqp->Type = UNKNOWN_TYPE;
    		break;
	}

	reqp->OnIOCompletion = storvsc_io_completion;
	reqp->SenseBuffer = (unsigned char *)  &csio->sense_data;
	reqp->SenseBufferSize = SSD_FULL_SIZE;
	reqp->Ccb = ccb;
	if (ccb->ccb_h.flags & CAM_SCATTER_VALID) {
		KASSERT(0, "ccb is scatter gather valid\n");
	}

	if (csio->dxfer_len != 0) {
		reqp->DataBuffer.Length = csio->dxfer_len;
		bytes_to_copy = csio->dxfer_len;
		phys_addr = vtophys(csio->data_ptr);
		reqp->DataBuffer.Offset = phys_addr - trunc_page(phys_addr);
	}

	while (bytes_to_copy != 0) {
		int bytes, page_offset;
		phys_addr = vtophys(&csio->data_ptr[reqp->DataBuffer.Length - bytes_to_copy]);
		pfn = phys_addr >> PAGE_SHIFT;
		reqp->DataBuffer.PfnArray[pfn_num] = pfn;
		page_offset = phys_addr - trunc_page(phys_addr);

		bytes = min(PAGE_SIZE - page_offset, bytes_to_copy);

		bytes_to_copy -= bytes;
		pfn_num++;
	}
		

	
}

static void
storvsc_io_completion(struct storvsc_request *reqp)
{
	union ccb *ccb = reqp->Ccb;
	struct storvsc_softc *sc = reqp->Softc;
	
	ccb->ccb_h.status &= ~(CAM_SIM_QUEUED);
	ccb->ccb_h.status |=  CAM_REQ_CMP;
	xpt_done(ccb);

	storvsc_free_request(sc, reqp);
}
	
static void
storvsc_free_request(struct storvsc_softc *sc, struct storvsc_request *reqp)
{
	struct storvsc_driver_context *sto_drv = sc->sto_drv;
	void *extp;

	ASSERT(reqp->Softc == sc);
	bzero(reqp->Extension, sto_drv->drv_obj.RequestExtSize);
	extp = reqp->Extension;
	reqp->Extension = NULL;
	bzero(reqp, sizeof(struct storvsc_request));
	reqp->Extension = extp;
	reqp->Softc = sc;

	mtx_lock(&sc->free_list_lock);
	LIST_INSERT_HEAD(&sc->free_list, reqp, link);
	mtx_unlock(&sc->free_list_lock);
}

static struct storvsc_driver_context *
storvsc_get_storage_type(device_t dev)
{
	const char *p = vmbus_get_type(dev);
	struct storvsc_driver_context *storvsc_ptr;

	if (!memcmp(p, &g_blkvsc_drv.drv_obj.Base.deviceType, sizeof(GUID))) {
		device_set_desc(dev, "Hyper-v IDE Storage Interface");
		storvsc_ptr = &g_blkvsc_drv;
	} else if (!memcmp(p, &g_storvsc_drv.drv_obj.Base.deviceType, sizeof(GUID))) {
		device_set_desc(dev, "Hyper-v SCSI Storage Interface");
		storvsc_ptr = &g_storvsc_drv;
	} else {
		storvsc_ptr = NULL;
	}
	return (storvsc_ptr);
}


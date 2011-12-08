#include <sys/types.h>
#include <sys/param.h>
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
	// !! These must be the first 2 fields !!
	struct driver_context   drv_ctx;
	STORVSC_DRIVER_OBJECT   drv_obj;
};

struct storvsc_softc {
	DEVICE_OBJECT *storvsc_dev;
	int unit;
	struct cam_sim *sim;
	struct cam_path *path;
	LIST_ENTRY free_list;
	HANDLE free_list_lock;
};

// The one and only one
static struct storvsc_driver_context g_storvsc_drv;
static void storvsc_io_completion(STORVSC_REQUEST *reqp);

/* static functions */
static int storvsc_probe(device_t dev);
static int storvsc_attach(device_t dev);
static void storvsc_init(void);
static int storvsc_detach(device_t dev);
static int storvsc_drv_init(PFN_DRIVERINITIALIZE pfn_drv_init);
static void storvsc_poll(struct cam_sim * sim);
static void storvsc_action(struct cam_sim * sim, union ccb * ccb);
static void scan_for_luns(struct storvsc_softc * storvsc_softc);
static void create_storvsc_request(union ccb *ccb, STORVSC_REQUEST *reqp);
static void storvsc_free_request(struct storvsc_softc *sc, STORVSC_REQUEST *reqp);

static device_method_t storvsc_methods[] = {
        /* Device interface */
        DEVMETHOD(device_probe,         storvsc_probe),
        DEVMETHOD(device_attach,        storvsc_attach),
        DEVMETHOD(device_detach,        storvsc_detach),
        DEVMETHOD(device_shutdown,      bus_generic_shutdown),
        { 0, 0 }
};

static driver_t storvsc_driver = {
        "storvsc", storvsc_methods, sizeof(struct storvsc_softc),
};

static devclass_t storvsc_devclass;
DRIVER_MODULE(storvsc, vmbus, storvsc_driver, storvsc_devclass, 0, 0);
MODULE_DEPEND(storvsc, vmbus, 1, 1, 1);
MODULE_VERSION(storvsc, 1);
SYSINIT(storvsc_initx, SI_SUB_RUN_SCHEDULER, SI_ORDER_MIDDLE + 1, storvsc_init, NULL);

static void
xptscandone(struct cam_periph *periph, union ccb *done_ccb)
{
        xpt_release_path(done_ccb->ccb_h.path);
        free(done_ccb->ccb_h.path, M_CAMXPT);
        free(done_ccb, M_CAMXPT);
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
static void scan_for_luns(struct storvsc_softc * storvsc_softc)
{
	union ccb *request_ccb;
	struct cam_path *path = storvsc_softc->path;
	struct cam_path *new_path = NULL;
	cam_status status;
	int i;
	
	for (i = 0; i < STORVSC_MAX_LUNS_PER_TARGET; i++) {

		request_ccb = malloc(sizeof(union ccb), M_CAMXPT, M_NOWAIT);
		if (request_ccb == NULL) {
			xpt_print(path, "scan_for_luns: can't allocate CCB, "
					  "can't continue\n");
			return;
		}
		new_path = malloc(sizeof(*new_path), M_CAMXPT, M_NOWAIT);
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
								  i);

		if (status != CAM_REQ_CMP) {
			xpt_print(path, "scan_for_luns: can't compile path, "
					  "can't continue\n");
			free(request_ccb, M_CAMXPT);
			free(new_path, M_CAMXPT);
			return;
		}

		xpt_setup_ccb(&request_ccb->ccb_h, new_path, CAM_PRIORITY_XPT);
		request_ccb->ccb_h.func_code = XPT_SCAN_LUN;
		request_ccb->ccb_h.cbfcnp = xptscandone;
		request_ccb->crcn.flags = CAM_FLAG_NONE;
		xpt_action(request_ccb);
	}
}

static int
storvsc_probe(device_t dev)
{
		const char *p = vmbus_get_type(dev);
        if (!memcmp(p, &g_storvsc_drv.drv_obj.Base.deviceType, sizeof(GUID))) {
                device_set_desc(dev, "Synthetic Storage Interface");
                printf("Storvsc probe ....DONE \n");
                return (0);
        }

        return (ENXIO);
}

static void storvsc_init(void)
{
        DPRINT_ENTER(STORVSC_DRV);
        printf("Storvsc initializing....");

        storvsc_drv_init(StorVscInitialize);

        DPRINT_EXIT(STORVSC_DRV);
}

/*++

Name:   storvsc_drv_init()

Desc:   StorVsc driver initialization

--*/
static int storvsc_drv_init(PFN_DRIVERINITIALIZE pfn_drv_init)
{
        int ret=0;
        STORVSC_DRIVER_OBJECT *stor_drv_obj=&g_storvsc_drv.drv_obj;
        struct driver_context *drv_ctx=&g_storvsc_drv.drv_ctx;

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
	STORVSC_DRIVER_OBJECT *storvsc_drv_obj=&g_storvsc_drv.drv_obj;
	struct device_context *device_ctx = vmbus_get_devctx(dev);

	STORVSC_DEVICE_INFO device_info;
	struct storvsc_softc *sc;
    struct cam_devq *devq;
	int ret, i;
	STORVSC_REQUEST *reqp;
	LIST_ENTRY *entry;

	
	sc = device_get_softc(dev);
	if (sc == NULL) {
		DPRINT_ERR(STORVSC_DRV, "softc not configured");
		ret = ENOMEM;
		return ret;
	}

	if (!storvsc_drv_obj->Base.OnDeviceAdd) {
		DPRINT_ERR(STORVSC_DRV, "OnDeviceAdd is not initialized");
		return -1;
	}

	bzero(sc, sizeof(struct storvsc_softc));
	device_ctx->device_obj.Driver = &g_storvsc_drv.drv_obj.Base;

	sc->unit = device_get_unit(dev);

	sc->storvsc_dev = &device_ctx->device_obj;

	INITIALIZE_LIST_HEAD(&sc->free_list);
	sc->free_list_lock = SpinlockCreate();

	for (i = 0; i < (STORVSC_MAX_IO_REQUESTS * STORVSC_MAX_TARGETS); ++i) {
		reqp = MemAllocZeroed(sizeof(STORVSC_REQUEST));
		if (reqp == NULL) {
			printf("cannot alloc STORVSC_REQUEST\n");
			goto cleanup;
		}

		reqp->Softc = sc;

		reqp->Extension = MemAllocZeroed(storvsc_drv_obj->RequestExtSize);
		if (reqp->Extension == NULL) {
			printf("cannot alloc request extension\n");
			goto cleanup;
		}

		INSERT_TAIL_LIST(&sc->free_list, &reqp->ListEntry);
	}

	ret = storvsc_drv_obj->Base.OnDeviceAdd(&device_ctx->device_obj, (void*)&device_info);

	if (ret != 0) {
		DPRINT_ERR(STORVSC_DRV, "unable to add storvsc device (ret %d)", ret);
		
		return ret;
	}

	// Create the device queue.
	// Hyper-V maps each target to one SCSI HBA
	devq = cam_simq_alloc(STORVSC_MAX_IO_REQUESTS * STORVSC_MAX_TARGETS);
	if (devq == NULL) {
		printf("Failed to alloc device queue\n");
		return (ENOMEM);
	}

	// XXX avoid Giant?
	sc->sim = cam_sim_alloc(storvsc_action, storvsc_poll, "vscsi", sc, sc->unit, &Giant, 1,
							STORVSC_MAX_IO_REQUESTS * STORVSC_MAX_TARGETS, devq);

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
	
	return 0;

 cleanup:

	while (!IS_LIST_EMPTY(&sc->free_list)) {
		entry = REMOVE_HEAD_LIST(&sc->free_list);
		reqp = CONTAINING_RECORD(entry, STORVSC_REQUEST, ListEntry);
		if (reqp->Extension) {
			MemFree(reqp->Extension);
		}
		MemFree(reqp);
	}
	return -1;
}
static int storvsc_detach(device_t dev)
{
	struct storvsc_softc *sc = device_get_softc(dev);
	STORVSC_REQUEST *reqp = NULL;
	LIST_ENTRY *entry;

	SpinlockAcquire(sc->free_list_lock);
	while (!IS_LIST_EMPTY(&sc->free_list)) {
		entry = REMOVE_HEAD_LIST(&sc->free_list);
		reqp = CONTAINING_RECORD(entry, STORVSC_REQUEST, ListEntry);
		if (reqp->Extension) {
			MemFree(reqp->Extension);
		}
		MemFree(reqp);
	}
	SpinlockRelease(sc->free_list_lock);
	return 0;
}

static void storvsc_poll(struct cam_sim *sim)
{
}

static void storvsc_action(struct cam_sim *sim, union ccb *ccb)
{
	struct storvsc_softc *sc = cam_sim_softc(sim);
	STORVSC_DRIVER_OBJECT *stor_drv_obj = &g_storvsc_drv.drv_obj;


    switch (ccb->ccb_h.func_code) {
	case XPT_PATH_INQ: {
		struct ccb_pathinq *cpi = &ccb->cpi;
		DPRINT_INFO(STORVSC, "XPT_PATH_INQ %d:%d:%d %s\n", cam_sim_bus(sim),
					ccb->ccb_h.target_id, ccb->ccb_h.target_lun, cam_sim_name(sim));

		cpi->version_num = 1;
		cpi->hba_inquiry = PI_TAG_ABLE|PI_SDTR_ABLE;
		cpi->target_sprt = 0;
		cpi->hba_misc = 0;
		cpi->hba_eng_cnt = 0;
		cpi->max_target = STORVSC_MAX_TARGETS;
		cpi->max_lun = STORVSC_MAX_LUNS_PER_TARGET;
		cpi->initiator_id = 0;
		cpi->bus_id = cam_sim_bus(sim);
		cpi->base_transfer_speed = 300000;
		cpi->transport = XPORT_SAS;
		cpi->transport_version = 0;
		cpi->protocol = PROTO_SCSI;
		cpi->protocol_version = SCSI_REV_SPC2;
		strncpy(cpi->sim_vid, "FreeBSD", SIM_IDLEN);
		strncpy(cpi->hba_vid, "STORVSC", HBA_IDLEN);
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
	case  XPT_RESET_BUS: {
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		return;
	}
	case  XPT_RESET_DEV:{
		ccb->ccb_h.status = CAM_REQ_CMP;
		xpt_done(ccb);
		return;
	}
	case XPT_SCSI_IO:
	case XPT_IMMED_NOTIFY: {
		struct ccb_scsiio *csio = &ccb->csio;
		STORVSC_REQUEST *reqp = NULL;
        int res;
		LIST_ENTRY *entry;
		uint8_t scsiio_code;

		if (csio->cdb_len > 0) {
			if(ccb->ccb_h.flags & CAM_CDB_POINTER) {
				scsiio_code = csio->cdb_io.cdb_ptr[0];
				//printf("scsi cmd 0x%x ptr\n", scsiio_code);
				
			} else {
				scsiio_code = csio->cdb_io.cdb_bytes[0];
				//printf("scsi cmd 0x%x bytes\n", scsiio_code);
			}
		} else {
			panic("cdb_len is 0\n");
		}

		if (scsiio_code == 0x12) {
			if(ccb->ccb_h.flags & CAM_CDB_POINTER) {
				//printf("SCSI_INQUIRY page 0x%x\n", csio->cdb_io.cdb_ptr[2]);
			} else {
				//printf("SCSI_INQUIRY page 0x%x\n", csio->cdb_io.cdb_bytes[2]);
			}
		}

		SpinlockAcquire(sc->free_list_lock);
		if (IS_LIST_EMPTY(&sc->free_list)) {
			printf("no free requests\n");
			ccb->ccb_h.status = CAM_PROVIDE_FAIL;
			xpt_done(ccb);
			SpinlockRelease(sc->free_list_lock);
			return;
		}

		entry = REMOVE_HEAD_LIST(&sc->free_list);
		reqp = CONTAINING_RECORD(entry, STORVSC_REQUEST, ListEntry);
		SpinlockRelease(sc->free_list_lock);
		ASSERT(reqp);

        ccb->ccb_h.status = CAM_SIM_QUEUED;	    

		create_storvsc_request(ccb, reqp);
		// XXX we need to consider if the vmbus channel can service this request
		// If not, we need to do some kind of queuing and deferred processing
		// until there is space in the ring buffer
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
		ccb->ccb_h.status = CAM_PROVIDE_FAIL;
		xpt_done(ccb);
        panic("Unsupported command\n");
		return;
	}
}

static void create_storvsc_request(union ccb *ccb, STORVSC_REQUEST *reqp)
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

static void storvsc_io_completion(STORVSC_REQUEST *reqp)
{
	union ccb *ccb = reqp->Ccb;
	struct storvsc_softc *sc = reqp->Softc;
	
	ccb->ccb_h.status &= ~(CAM_SIM_QUEUED);
	ccb->ccb_h.status |=  CAM_REQ_CMP;
	xpt_done(ccb);

	storvsc_free_request(sc, reqp);
}
	
static void storvsc_free_request(struct storvsc_softc *sc, STORVSC_REQUEST *reqp)
{
	STORVSC_DRIVER_OBJECT *storvsc_drv_obj=&g_storvsc_drv.drv_obj;
	void *extp;

	ASSERT(reqp->Softc == sc);
	bzero(reqp->Extension, storvsc_drv_obj->RequestExtSize);
	extp = reqp->Extension;
	reqp->Extension = NULL;
	bzero(reqp, sizeof(STORVSC_REQUEST));
	reqp->Extension = extp;
	reqp->Softc = sc;

	SpinlockAcquire(sc->free_list_lock);
	INSERT_TAIL_LIST(&sc->free_list, &reqp->ListEntry);
	SpinlockRelease(sc->free_list_lock);

}






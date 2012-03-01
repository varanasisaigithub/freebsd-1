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

#include <hv_vmbus_var.h>
#include <hv_vmbus.h>
#include <hv_logging.h>

#include "hv_stor_vsc_api.h"

struct storvsc_driver_props {
	char		*drv_name;
	char		*drv_desc;
	uint8_t		drv_max_luns_per_target;
	uint8_t		drv_max_ios_per_target;
	uint32_t	drv_ringbuffer_size;
};

enum hv_storage_type {
	DRIVER_BLKVSC,
	DRIVER_STORVSC,
	DRIVER_UNKNOWN
};

/* {ba6163d9-04a1-4d29-b605-72e2ffb1dc7f} */
static const GUID gStorVscDeviceType={
	.Data = {0xd9, 0x63, 0x61, 0xba, 0xa1, 0x04, 0x29, 0x4d, 0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f}
};

/* {32412632-86cb-44a2-9b5c-50d1417354f5} */
static const GUID gBlkVscDeviceType={
	.Data = {0x32, 0x26, 0x41, 0x32, 0xcb, 0x86, 0xa2, 0x44, 0x9b, 0x5c, 0x50, 0xd1, 0x41, 0x73, 0x54, 0xf5}
};

static struct storvsc_driver_props g_drv_props_table[] = {
	{"blkvsc", "Hyper-V IDE Storage Interface",
	 BLKVSC_MAX_IDE_DISKS_PER_TARGET, BLKVSC_MAX_IO_REQUESTS,
	 STORVSC_RINGBUFFER_SIZE},
	{"storvsc", "Hyper-V SCSI Storage Interface",
	 STORVSC_MAX_LUNS_PER_TARGET, STORVSC_MAX_IO_REQUESTS,
	 STORVSC_RINGBUFFER_SIZE}
};

struct storvsc_softc {
	DEVICE_OBJECT *storvsc_dev;
	LIST_HEAD(, hv_storvsc_request) free_list;
	struct mtx free_list_lock;
	struct storvsc_driver_object  drv_obj;
	struct storvsc_driver_props	 *drv_props;
	int unit;
	struct cam_sim *sim;
	struct cam_path *path;

};

/* static functions */
static int storvsc_probe(device_t dev);
static int storvsc_attach(device_t dev);
static int storvsc_detach(device_t dev);
static void storvsc_poll(struct cam_sim * sim);
static void storvsc_action(struct cam_sim * sim, union ccb * ccb);
static void scan_for_luns(struct storvsc_softc * storvsc_softc);
static void create_storvsc_request(union ccb *ccb, struct hv_storvsc_request *reqp);
static void storvsc_free_request(struct storvsc_softc *sc, struct hv_storvsc_request *reqp);
static enum hv_storage_type storvsc_get_storage_type(device_t dev);

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

extern int ata_disk_enable;

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
	if (++lun_nb < storvsc_softc->drv_props->drv_max_luns_per_target) {
	
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
	int ret	= ENXIO;

	switch (storvsc_get_storage_type(dev)) {
	case DRIVER_BLKVSC:
		if (ata_disk_enable == 0) {
			ret = 0;
		}
		break;
	case DRIVER_STORVSC:
		ret = 0;
		break;
	default:
		ret = ENXIO;
	}

	return (ret);
}

static int
storvsc_attach(device_t dev)
{
	struct device_context *device_ctx = vmbus_get_devctx(dev);
	enum hv_storage_type stor_type;
	struct storvsc_softc *sc;
	struct cam_devq *devq;
	int ret, i;
	struct hv_storvsc_request *reqp;

	DPRINT_ENTER(STORVSC_DRV);

	sc = device_get_softc(dev);
	if (sc == NULL) {
		DPRINT_ERR(STORVSC_DRV, "softc not configured");
		ret = ENOMEM;
		return ret;
	}

	stor_type = storvsc_get_storage_type(dev);
	if (stor_type == DRIVER_UNKNOWN) {
		DPRINT_ERR(STORVSC_DRV, "Not a storage device");
		return (-1);
	}

	bzero(sc, sizeof(struct storvsc_softc));

	/* fill in driver specific properties */
	sc->drv_obj.Base.name = g_drv_props_table[stor_type].drv_name;
	sc->drv_props = &g_drv_props_table[stor_type];
	sc->drv_obj.ringbuffer_size =
		g_drv_props_table[stor_type].drv_ringbuffer_size;

	device_ctx->device_obj.Driver = &sc->drv_obj.Base;

	/* fill in device specific properties */
	sc->unit	= device_get_unit(dev);
	sc->storvsc_dev = &device_ctx->device_obj;
	device_set_desc(dev, g_drv_props_table[stor_type].drv_desc);

	LIST_INIT(&sc->free_list);
	mtx_init(&sc->free_list_lock, "storvsc free list lock", NULL,
			 MTX_SPIN | MTX_RECURSE);

	for (i = 0; i < sc->drv_props->drv_max_ios_per_target; ++i) {
		reqp = malloc(sizeof(struct hv_storvsc_request), M_DEVBUF,
					  M_NOWAIT | M_ZERO);
		if (reqp == NULL) {
			printf("cannot alloc struct hv_storvsc_request\n");
			goto cleanup;
		}

		reqp->softc = sc;

		LIST_INSERT_HEAD(&sc->free_list, reqp, link);
	}

	ret = hv_storvsc_on_deviceadd(&device_ctx->device_obj);

	if (ret != 0) {
		DPRINT_ERR(STORVSC_DRV, "unable to add storvsc device (ret %d)", ret);
		
		return ret;
	}

	/*
	 *  Create the device queue.
	 * Hyper-V maps each target to one SCSI HBA
	 */
	devq = cam_simq_alloc(sc->drv_props->drv_max_ios_per_target);
	if (devq == NULL) {
		printf("Failed to alloc device queue\n");
		return (ENOMEM);
	}

	/* XXX avoid Giant? */
	sc->sim = cam_sim_alloc(storvsc_action,
				storvsc_poll,
				sc->drv_props->drv_name,
				sc,
				sc->unit,
				&Giant, 1,
				sc->drv_props->drv_max_ios_per_target,
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

		free(reqp, M_DEVBUF);
	}
	return -1;
}

static int storvsc_detach(device_t dev)
{
	struct storvsc_softc *sc = device_get_softc(dev);
	struct hv_storvsc_request *reqp = NULL;

	/* XXX call hv_storvsc_on_deviceremove? */

	mtx_lock(&sc->free_list_lock);
	while (!LIST_EMPTY(&sc->free_list)) {
		reqp = LIST_FIRST(&sc->free_list);
		LIST_REMOVE(reqp, link);

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
	int res;

	switch (ccb->ccb_h.func_code) {
	case XPT_PATH_INQ: {
		struct ccb_pathinq *cpi = &ccb->cpi;
		DPRINT_INFO(STORVSC, "XPT_PATH_INQ %d:%d:%d %s\n", cam_sim_bus(sim),
					ccb->ccb_h.target_id, ccb->ccb_h.target_lun,
					cam_sim_name(sim));

		cpi->version_num = 1;
		cpi->hba_inquiry = PI_TAG_ABLE|PI_SDTR_ABLE;
		cpi->target_sprt = 0;
		cpi->hba_misc = PIM_NOBUSRESET;
		cpi->hba_eng_cnt = 0;
		cpi->max_target = STORVSC_MAX_TARGETS;
		cpi->max_lun = sc->drv_props->drv_max_luns_per_target;
		cpi->initiator_id = 0;
		cpi->bus_id = cam_sim_bus(sim);
		cpi->base_transfer_speed = 300000;
		cpi->transport = XPORT_SAS;
		cpi->transport_version = 0;
		cpi->protocol = PROTO_SCSI;
		cpi->protocol_version = SCSI_REV_SPC2;
		strncpy(cpi->sim_vid, "FreeBSD", SIM_IDLEN);
		strncpy(cpi->hba_vid, sc->drv_props->drv_name, HBA_IDLEN);
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

		/* Enable tag queuing and disconnected mode */
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
		if ((res = hv_storvsc_host_reset(sc->storvsc_dev)) != 0) {
			printf("hv_storvsc_host_reset failed with %d\n", res);
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
		struct hv_storvsc_request *reqp = NULL;

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
		if ((res = hv_storvsc_io_request(sc->storvsc_dev, reqp)) == -1) {
			printf("hv_storvsc_io_request failed with %d\n", res);
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
create_storvsc_request(union ccb *ccb, struct hv_storvsc_request *reqp)
{
	struct ccb_scsiio *csio = &ccb->csio;
	uint64_t phys_addr;
	uint32_t bytes_to_copy = 0;
	uint32_t pfn_num = 0;
	uint32_t pfn;
	
	reqp->vstor_packet.vm_srb.port = cam_sim_unit(xpt_path_sim(ccb->ccb_h.path));
	reqp->vstor_packet.vm_srb.target_id = ccb->ccb_h.target_id;
	reqp->vstor_packet.vm_srb.path_id =  ccb->ccb_h.path_id;
	reqp->vstor_packet.vm_srb.lun = ccb->ccb_h.target_lun;

	reqp->vstor_packet.vm_srb.cdb_len = csio->cdb_len;
	if(ccb->ccb_h.flags & CAM_CDB_POINTER) {
		memcpy(&reqp->vstor_packet.vm_srb.cdb, csio->cdb_io.cdb_ptr, csio->cdb_len);
	} else {
		memcpy(&reqp->vstor_packet.vm_srb.cdb, csio->cdb_io.cdb_bytes, csio->cdb_len);
	}

	switch (ccb->ccb_h.flags & CAM_DIR_MASK) {
    	case CAM_DIR_OUT: 
    		reqp->vstor_packet.vm_srb.data_in = WRITE_TYPE;
    		break;
    	case CAM_DIR_IN:
    		reqp->vstor_packet.vm_srb.data_in = READ_TYPE;
    		break;
    	case CAM_DIR_NONE:
    		reqp->vstor_packet.vm_srb.data_in = UNKNOWN_TYPE;
    		break;
    	default:
    		reqp->vstor_packet.vm_srb.data_in = UNKNOWN_TYPE;
    		break;
	}

	reqp->sense_data = (uint8_t *)&csio->sense_data;
	reqp->sense_info_len = csio->sense_len;

	reqp->ccb = ccb;
	if (ccb->ccb_h.flags & CAM_SCATTER_VALID) {
		KASSERT(0, "ccb is scatter gather valid\n");
	}

	if (csio->dxfer_len != 0) {
		reqp->data_buf.Length = csio->dxfer_len;
		bytes_to_copy = csio->dxfer_len;
		phys_addr = vtophys(csio->data_ptr);
		reqp->data_buf.Offset = phys_addr - trunc_page(phys_addr);
	}

	while (bytes_to_copy != 0) {
		int bytes, page_offset;
		phys_addr = vtophys(&csio->data_ptr[reqp->data_buf.Length - bytes_to_copy]);
		pfn = phys_addr >> PAGE_SHIFT;
		reqp->data_buf.PfnArray[pfn_num] = pfn;
		page_offset = phys_addr - trunc_page(phys_addr);

		bytes = min(PAGE_SIZE - page_offset, bytes_to_copy);

		bytes_to_copy -= bytes;
		pfn_num++;
	}
		
}

/*
 * storvsc_io_done
 *
 * I/O process has been completed and the result needs
 * to be passed to the CAM layer.
 * Free resources related to this request.
 */
void
storvsc_io_done(struct hv_storvsc_request *reqp)
{
	union ccb *ccb = reqp->ccb;
	struct ccb_scsiio *csio = &ccb->csio;
	struct storvsc_softc *sc = reqp->softc;
	struct vmscsi_req *vm_srb = &reqp->vstor_packet.vm_srb;
	
	ccb->ccb_h.status &= ~(CAM_SIM_QUEUED);
	ccb->ccb_h.status &= ~CAM_STATUS_MASK;

	if (vm_srb->scsi_status == SCSI_STATUS_OK) {
		ccb->ccb_h.status |=  CAM_REQ_CMP;
	} else {
		ccb->ccb_h.status |= CAM_SCSI_STATUS_ERROR;
	}

	ccb->csio.scsi_status = (vm_srb->scsi_status & 0xFF);
	ccb->csio.resid = ccb->csio.dxfer_len - vm_srb->transfer_len;

	if (reqp->sense_info_len != 0) {
		ASSERT(reqp->sense_info_len <= csio->sense_len);
		csio->sense_resid = csio->sense_len - reqp->sense_info_len;
		ccb->ccb_h.status |= CAM_AUTOSNS_VALID;
	}

	xpt_done(ccb);

	storvsc_free_request(sc, reqp);
}
	
static void
storvsc_free_request(struct storvsc_softc *sc, struct hv_storvsc_request *reqp)
{
	ASSERT(reqp->softc == sc);
	bzero(reqp, sizeof(struct hv_storvsc_request));
	reqp->softc = sc;

	mtx_lock(&sc->free_list_lock);
	LIST_INSERT_HEAD(&sc->free_list, reqp, link);
	mtx_unlock(&sc->free_list_lock);
}

static enum hv_storage_type
storvsc_get_storage_type(device_t dev)
{
	const char *p = vmbus_get_type(dev);

	if (!memcmp(p, &gBlkVscDeviceType, sizeof(GUID))) {
		return DRIVER_BLKVSC;
	} else if (!memcmp(p, &gStorVscDeviceType, sizeof(GUID))) {
		return DRIVER_STORVSC;
	}
	return (DRIVER_UNKNOWN);
}


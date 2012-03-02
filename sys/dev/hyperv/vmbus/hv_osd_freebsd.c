/*****************************************************************************
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The following copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2010-2011, Citrix, Inc.
 *
 * HyperV FreeBSD poerating system dependent code
 *
 *****************************************************************************/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/callout.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kthread.h>
#include <sys/taskqueue.h>
#include <sys/smp.h>

#include <machine/stdarg.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>

#include <vm/pmap.h>

#include <machine/bus.h>
#include <sys/timetc.h>

#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>

typedef long wait_queue_head_t;
typedef struct mtx SPINLOCK;

//
// Data types
//

typedef struct _TIMER {
	struct callout_handle handle;
	PFN_TIMER_CALLBACK callback;
	void *context;
} TIMER;

typedef struct _WAITEVENT {
	int condition;
	struct mtx mtx;
	wait_queue_head_t event;
} WAITEVENT;

typedef struct _WORKQUEUE {
	struct taskqueue *queue;
	struct proc *proc;
} WORKQUEUE;

typedef struct _WORKITEM {
	struct task work;
	PFN_WORKITEM_CALLBACK callback;
	void *context;
} WORKITEM;

static void TimerCallback(void *);
static void WorkItemCallback(void *work, int pending);

/* Use critical sections for spinlocks */
// #define USE_CRITICAL_SECTION 1
//
// Global
//
/* External Interfaces */

void BitSet(unsigned int *addr, int bit)
{
	__asm__("bts %1,%0" : "+m" (*addr) : "Ir" (bit));
}

int BitTest(unsigned int *addr, int bit) {
	unsigned char v;

    __asm__("btl %2,%1; setc %0" : "=qm" (v) : "m" (*addr), "Ir" (bit));
	return ((int) v);
}

void BitClear(unsigned int *addr, int bit)
{
	__asm__("btr %1,%0" : "+m" (*addr) : "Ir" (bit));
}

int BitTestAndClear(unsigned int *addr, int bit) {
	int oldbit;

	__asm__ __volatile__("lock; btr %2,%1; sbb %0,%0"
		: "=r" (oldbit), "+m" (*addr) : "Ir" (bit) : "memory");

	return (oldbit);
}

int BitTestAndSet(unsigned int *addr, int bit) {
	int oldbit;

	__asm__ __volatile__("lock; bts %2,%1; sbb %0,%0"
		: "=r" (oldbit), "+m" (*addr) : "Ir" (bit) : "memory");

	return (oldbit);
}

static inline int atomic_add_return(int i, int *addr) {
	int __i = i;
	__asm__ __volatile__("lock; xadd %0, %1"
			: "+r" (i), "+m" (*addr)
			: : "memory");
	return (i + __i);
}

int InterlockedIncrement(int *val) {
	return (atomic_add_return(1, val));
}

int InterlockedDecrement(int *val) {
	return (atomic_add_return(-1, val));
}

int InterlockedCompareExchange(int *val, int new, int curr) {
	int prev;

	__asm__ __volatile__("lock; cmpxchg %1,%2"
		: "=a"(prev)
		: "r"(new), "m"(*val), "0"(curr)
		: "memory");

	return (prev);
}

void Sleep(unsigned long usecs) {
	DELAY(usecs);
}

void *VirtualAllocExec(unsigned int size) {
	void *p;

	p = malloc(size, M_DEVBUF, M_WAITOK|M_ZERO);

	return (p);
}

void VirtualFree(void *VirtAddr) {
	return (free(VirtAddr, M_DEVBUF));
}

void *PageAlloc(unsigned int count) {
	void *p;

	p = contigmalloc(count * PAGE_SIZE, M_DEVBUF, M_WAITOK,
		BUS_SPACE_MAXADDR_24BIT, BUS_SPACE_MAXADDR, PAGE_SIZE, 0);
	if (p) {
		memset(p, 0, count * PAGE_SIZE);
	}

	return (p);
}

void PageFree(void *page, unsigned int count) {
	contigfree(page, PAGE_SIZE * count, M_DEVBUF);
}

/*
 *
 */
void *PageMapVirtualAddress(unsigned long Pfn) {
	unsigned long va = Pfn << PAGE_SHIFT;
//	invlpg(va);
	return ((void *) (va));
}

void PageUnmapVirtualAddress(void *VirtAddr) {
}

void *MemAlloc(unsigned int size) {
	return (malloc(size, M_DEVBUF, M_NOWAIT));
}

void *MemAllocZeroed(unsigned int size) {
	return (malloc(size, M_DEVBUF, M_NOWAIT|M_ZERO));
}

void *MemAllocAtomic(unsigned int size) {
	return (malloc(size, M_DEVBUF, M_NOWAIT));
}

void MemFree(void *buf) {
	free(buf, M_DEVBUF);
}

void *MemMapIO(unsigned long phys, unsigned long size) {
	/* no users of this function */
	printf("MemMapIO - Error\n");

	return (NULL);
}

void MemUnmapIO(void *virt) {
	/* Fixme:  Implement it */
	printf("MemUnmapIO - Error\n");
}


void MemoryFence()
{
	__asm __volatile__("mfence" ::: "memory");
}

static void TimerCallback(void *data) {
	TIMER *t = (TIMER*) data;

	t->callback(t->context);
}

HANDLE TimerCreate(PFN_TIMER_CALLBACK pfnTimerCB, void *context) {
	TIMER *t = malloc(sizeof(TIMER), M_DEVBUF, M_NOWAIT);
	if (!t) {
		printf("Failed to create timer\n");
		return (NULL);
	}

	t->callback = pfnTimerCB;
	t->context = context;
	callout_handle_init(&t->handle);

	return (t);
}

void TimerStart(HANDLE hTimer, uint32_t expirationInUs) {
	TIMER *t = (TIMER *) hTimer;

	t->handle = timeout(TimerCallback, t, expirationInUs / 1000);
}

int TimerStop(HANDLE hTimer) {
	TIMER *t = (TIMER *) hTimer;

	untimeout(TimerCallback, t, t->handle);

	return (0);
}

void TimerClose(HANDLE hTimer) {
	TIMER *t = (TIMER *) hTimer;

	untimeout(TimerCallback, t, t->handle);

	free(t, M_DEVBUF);
}

/* Not used */
size_t GetTickCount(void) {
	return (ticks);
}

#ifdef LATER
static signed long long GetTimestamp(void)
{
	struct timespec ts;

	nanotime(&ts);
	return (ts.tv_sec * 1000000000 + ts.tv_nsec);
}
#endif

HANDLE WaitEventCreate(void) {
	WAITEVENT *wait = malloc(sizeof(WAITEVENT), M_DEVBUF, M_WAITOK|M_ZERO);
	if (!wait) {
		printf("Failed to create WaitEvent\n");
		return (NULL);
	}

	wait->condition = 0;
	mtx_init(&wait->mtx, "HV Wait Event", NULL, MTX_RECURSE);

	return (wait);
}

void WaitEventClose(HANDLE hWait) {
	WAITEVENT *waitEvent = (WAITEVENT *)hWait;

	/* Do we need to care about the waiting processes - if any */
	mtx_destroy(&waitEvent->mtx);
	free(waitEvent, M_DEVBUF);
}

void WaitEventSet(HANDLE hWait) {
	WAITEVENT *waitEvent = (WAITEVENT *)hWait;
#if 1
	mtx_lock(&waitEvent->mtx);
	waitEvent->condition = 1;
	wakeup(&waitEvent->event);
	mtx_unlock(&waitEvent->mtx);
#else
	wakeup(&waitEvent->event);
#endif
}

int WaitEventWait(HANDLE hWait) {
	int ret = 0;
	WAITEVENT *waitEvent = (WAITEVENT *)hWait;

#if 1
	mtx_lock(&waitEvent->mtx);
	if (waitEvent->condition) {
		waitEvent->condition = 0;
	} else {
		ret = msleep(&waitEvent->event, &waitEvent->mtx,
			PWAIT | PCATCH, "hv sleep", 0);
//		if (ret == 0)
		waitEvent->condition = 0;
	}
	mtx_unlock(&waitEvent->mtx);
#else
	ret = tsleep(&waitEvent->event, PWAIT | PCATCH, "hv sleep", 0);
#endif
	return (ret);
}

int WaitEventWaitEx(HANDLE hWait, uint32_t TimeoutInMs) {
	int ret = 1;
	WAITEVENT *waitEvent = (WAITEVENT *)hWait;

#if 1
	mtx_lock(&waitEvent->mtx);
	if (waitEvent->condition) {
		waitEvent->condition = 0;
	} else {
		ret = msleep(&waitEvent->event, &waitEvent->mtx,
			PWAIT | PCATCH, "hv sleep tw", TimeoutInMs);
		if (ret == 0) {
			ret = 1;
		} else if (ret == EWOULDBLOCK) {
			ret = 0;
		} else {
			ret = -ret;
		}
//		if (ret == 0)
		waitEvent->condition = 0;
	}
	mtx_unlock(&waitEvent->mtx);
#else
	ret = tsleep(&waitEvent->event, PWAIT | PCATCH, "hv sleep tw",
		TimeoutInMs);
#endif
	return (ret);
}

HANDLE SpinlockCreate(void) {
#ifdef USE_CRITICAL_SECTION
	return ((HANDLE)1);
#else
	SPINLOCK *spin = malloc(sizeof(SPINLOCK), M_DEVBUF, M_WAITOK|M_ZERO);
	mtx_init(spin, "HV spin lock", NULL, MTX_SPIN | MTX_RECURSE);

	return (spin);
#endif
}

void SpinlockAcquire(HANDLE hSpin) {
#ifdef USE_CRITICAL_SECTION
	critical_enter();
#else
	SPINLOCK *spin = (SPINLOCK *) hSpin;

	mtx_lock_spin(spin);
#endif
}

void SpinlockRelease(HANDLE hSpin) {
#ifdef USE_CRITICAL_SECTION
	critical_exit();
#else
	SPINLOCK *spin = (SPINLOCK *) hSpin;

	mtx_unlock_spin(spin);
#endif
}

void SpinlockClose(HANDLE hSpin) {
#ifdef USE_CRITICAL_SECTION
#else
	SPINLOCK *spin = (SPINLOCK *) hSpin;

	mtx_destroy(spin);
	free(spin, M_DEVBUF);
#endif
}

void *Physical2LogicalAddr(unsigned long PhysAddr) {
	/* Should not be executed  - used in vmbus/hv.c */
	printf("NOTYET - Physical2LogicalAddr\n");

	return (NULL);
}

unsigned long Logical2PhysicalAddr(void *LogicalAddr) {
	unsigned long ret;

	ret = (vtophys(LogicalAddr) | ((vm_offset_t) LogicalAddr & PAGE_MASK));

	return (ret);
}

unsigned long Virtual2Physical(void *VirtAddr) {
	unsigned long ret;

	ret = vtophys(VirtAddr);

	return (ret);
}

static void WorkItemCallback(void *work, int pending) {
	WORKITEM *w = (WORKITEM*) work;

	critical_enter();
	w->callback(w->context);
	critical_exit();

	free(w, M_DEVBUF);
}

HANDLE WorkQueueCreate(char *name) {
	static unsigned int qid = 0;
	char qname[64];
	int pri;

	WORKQUEUE *wq = malloc(sizeof(WORKQUEUE), M_DEVBUF, M_NOWAIT);
	if (!wq) {
		printf("Failed to create WorkQueue\n");
		return (NULL);
	}

	if (strcmp(name, "vmbusQ") == 0) {
		pri = PI_DISK;
	} else {
		pri = PI_NET;
	}

	sprintf(qname, "hv_%s_%u", name, qid);

	/*
	 * Fixme:  FreeBSD 8.2 has a different prototype for
	 * taskqueue_create(), and for certain other taskqueue functions.
	 * We need to research the implications of these changes.
	 * Fixme:  Not sure when the changes were introduced.
	 */
	wq->queue = taskqueue_create(qname, M_NOWAIT, taskqueue_thread_enqueue,
		&wq->queue
#if __FreeBSD_version < 800000
		, &wq->proc
#endif
		);

	if (wq->queue == NULL) {
		free(wq, M_DEVBUF);
		return (NULL);
	}

	if (taskqueue_start_threads(&wq->queue, 1, pri, "%s taskq", qname)) {
		taskqueue_free(wq->queue);
		free(wq, M_DEVBUF);
		return (NULL);
	}

	qid++;

	return (wq);
}

void WorkQueueClose(HANDLE hWorkQueue) {
	WORKQUEUE *wq = (WORKQUEUE *) hWorkQueue;

//	taskqueue_drain(wq->tq, );
	taskqueue_free(wq->queue);
	free(wq, M_DEVBUF);
}

int WorkQueueQueueWorkItem(HANDLE hWorkQueue, PFN_WORKITEM_CALLBACK workItem,
	void *context) {
	WORKQUEUE *wq = (WORKQUEUE *) hWorkQueue;

	WORKITEM *w = malloc(sizeof(WORKITEM), M_DEVBUF, M_NOWAIT);
	if (!w) {
		printf("Failed to create WorkItem\n");
		return (-1);
	}

	w->callback = workItem;
	w->context = context;

	TASK_INIT(&w->work, 0, WorkItemCallback, w);

	return (taskqueue_enqueue(wq->queue, &w->work));
}

/* Not used */
void QueueWorkItem(PFN_WORKITEM_CALLBACK workItem, void *context) {
	(workItem)(context);
}

int getCpuId(void) {
	return (PCPU_GET(cpuid));
}

int doOnAllCpus(void(*func)(void *info), void *info, int retry, int wait) {
	smp_rendezvous(NULL, func, NULL, info);

	/* Fixme:  added this to silence a warning */
	return (0);
}

void*
PageAllocAtomic(unsigned int count) {
	void *p;

	p = contigmalloc(count * PAGE_SIZE, M_DEVBUF, M_WAITOK,
		BUS_SPACE_MAXADDR_24BIT, BUS_SPACE_MAXADDR, PAGE_SIZE, 0);
	if (p) {
		memset(p, 0, count * PAGE_SIZE);
	}
	return (p);
}


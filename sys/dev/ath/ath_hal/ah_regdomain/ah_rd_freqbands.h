/*
 * Copyright (c) 2002-2009 Sam Leffler, Errno Consulting
 * Copyright (c) 2005-2006 Atheros Communications, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $FreeBSD$
 */

#ifndef	__AH_REGDOMAIN_FREQBANDS_H__
#define	__AH_REGDOMAIN_FREQBANDS_H__

#define	AFTER(x)	((x)+1)

/*
 * Frequency band collections are defined using bitmasks.  Each bit
 * in a mask is the index of an entry in one of the following tables.
 * Bitmasks are BMLEN*64 bits so if a table grows beyond that the bit
 * vectors must be enlarged or the tables split somehow (e.g. split
 * 1/2 and 1/4 rate channels into a separate table).
 *
 * Beware of ordering; the indices are defined relative to the preceding
 * entry so if things get off there will be confusion.  A good way to
 * check the indices is to collect them in a switch statement in a stub
 * function so the compiler checks for duplicates.
 */

/*
 * 5GHz 11A channel tags
 */
static REG_DMN_FREQ_BAND regDmn5GhzFreq[] = {
	{ 4915, 4925, 23, 0, 10,  5, NO_DFS, PSCAN_MKK2 },
#define	F1_4915_4925	0
	{ 4935, 4945, 23, 0, 10,  5, NO_DFS, PSCAN_MKK2 },
#define	F1_4935_4945	AFTER(F1_4915_4925)
	{ 4920, 4980, 23, 0, 20, 20, NO_DFS, PSCAN_MKK2 },
#define	F1_4920_4980	AFTER(F1_4935_4945)
	{ 4942, 4987, 27, 6,  5,  5, NO_DFS, PSCAN_FCC },
#define	F1_4942_4987	AFTER(F1_4920_4980)
	{ 4945, 4985, 30, 6, 10,  5, NO_DFS, PSCAN_FCC },
#define	F1_4945_4985	AFTER(F1_4942_4987)
	{ 4950, 4980, 33, 6, 20,  5, NO_DFS, PSCAN_FCC },
#define	F1_4950_4980	AFTER(F1_4945_4985)
	{ 5035, 5040, 23, 0, 10,  5, NO_DFS, PSCAN_MKK2 },
#define	F1_5035_5040	AFTER(F1_4950_4980)
	{ 5040, 5080, 23, 0, 20, 20, NO_DFS, PSCAN_MKK2 },
#define	F1_5040_5080	AFTER(F1_5035_5040)
	{ 5055, 5055, 23, 0, 10,  5, NO_DFS, PSCAN_MKK2 },
#define	F1_5055_5055	AFTER(F1_5040_5080)

	{ 5120, 5240, 5,  6, 20, 20, NO_DFS, NO_PSCAN },
#define	F1_5120_5240	AFTER(F1_5055_5055)
	{ 5120, 5240, 5,  6, 10, 10, NO_DFS, NO_PSCAN },
#define	F2_5120_5240	AFTER(F1_5120_5240)
	{ 5120, 5240, 5,  6,  5,  5, NO_DFS, NO_PSCAN },
#define	F3_5120_5240	AFTER(F2_5120_5240)

	{ 5170, 5230, 23, 0, 20, 20, NO_DFS, PSCAN_MKK1 | PSCAN_MKK2 },
#define	F1_5170_5230	AFTER(F3_5120_5240)
	{ 5170, 5230, 20, 0, 20, 20, NO_DFS, PSCAN_MKK1 | PSCAN_MKK2 },
#define	F2_5170_5230	AFTER(F1_5170_5230)

	{ 5180, 5240, 15, 0, 20, 20, NO_DFS, PSCAN_FCC | PSCAN_ETSI },
#define	F1_5180_5240	AFTER(F2_5170_5230)
	{ 5180, 5240, 17, 6, 20, 20, NO_DFS, PSCAN_FCC },
#define	F2_5180_5240	AFTER(F1_5180_5240)
	{ 5180, 5240, 18, 0, 20, 20, NO_DFS, PSCAN_FCC | PSCAN_ETSI },
#define	F3_5180_5240	AFTER(F2_5180_5240)
	{ 5180, 5240, 20, 0, 20, 20, NO_DFS, PSCAN_FCC | PSCAN_ETSI },
#define	F4_5180_5240	AFTER(F3_5180_5240)
	{ 5180, 5240, 23, 0, 20, 20, NO_DFS, PSCAN_FCC | PSCAN_ETSI },
#define	F5_5180_5240	AFTER(F4_5180_5240)
	{ 5180, 5240, 23, 6, 20, 20, NO_DFS, PSCAN_FCC },
#define	F6_5180_5240	AFTER(F5_5180_5240)
	{ 5180, 5240, 17, 6, 20, 10, NO_DFS, PSCAN_FCC },
#define	F7_5180_5240	AFTER(F6_5180_5240)
	{ 5180, 5240, 17, 6, 20,  5, NO_DFS, PSCAN_FCC },
#define	F8_5180_5240	AFTER(F7_5180_5240)
	{ 5180, 5320, 20, 6, 20, 20, DFS_ETSI, PSCAN_ETSI },

#define	F1_5180_5320	AFTER(F8_5180_5240)
	{ 5240, 5280, 23, 0, 20, 20, DFS_FCC3, PSCAN_FCC | PSCAN_ETSI },

#define	F1_5240_5280	AFTER(F1_5180_5320)
	{ 5260, 5280, 23, 0, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC | PSCAN_ETSI },

#define	F1_5260_5280	AFTER(F1_5240_5280)
	{ 5260, 5320, 18, 0, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC | PSCAN_ETSI },

#define	F1_5260_5320	AFTER(F1_5260_5280)
	{ 5260, 5320, 20, 0, 20, 20, DFS_FCC3 | DFS_ETSI | DFS_MKK4, PSCAN_FCC | PSCAN_ETSI | PSCAN_MKK3  },
#define	F2_5260_5320	AFTER(F1_5260_5320)

	{ 5260, 5320, 20, 6, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC },
#define	F3_5260_5320	AFTER(F2_5260_5320)
	{ 5260, 5320, 23, 6, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC },
#define	F4_5260_5320	AFTER(F3_5260_5320)
	{ 5260, 5320, 23, 6, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC },
#define	F5_5260_5320	AFTER(F4_5260_5320)
	{ 5260, 5320, 30, 0, 20, 20, NO_DFS, NO_PSCAN },
#define	F6_5260_5320	AFTER(F5_5260_5320)
	{ 5260, 5320, 23, 6, 20, 10, DFS_FCC3 | DFS_ETSI, PSCAN_FCC },
#define	F7_5260_5320	AFTER(F6_5260_5320)
	{ 5260, 5320, 23, 6, 20,  5, DFS_FCC3 | DFS_ETSI, PSCAN_FCC },
#define	F8_5260_5320	AFTER(F7_5260_5320)

	{ 5260, 5700, 5,  6, 20, 20, DFS_FCC3 | DFS_ETSI, NO_PSCAN },
#define	F1_5260_5700	AFTER(F8_5260_5320)
	{ 5260, 5700, 5,  6, 10, 10, DFS_FCC3 | DFS_ETSI, NO_PSCAN },
#define	F2_5260_5700	AFTER(F1_5260_5700)
	{ 5260, 5700, 5,  6,  5,  5, DFS_FCC3 | DFS_ETSI, NO_PSCAN },
#define	F3_5260_5700	AFTER(F2_5260_5700)

	{ 5280, 5320, 17, 6, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC },
#define	F1_5280_5320	AFTER(F3_5260_5700)

	{ 5500, 5620, 30, 6, 20, 20, DFS_ETSI, PSCAN_ETSI },
#define	F1_5500_5620	AFTER(F1_5280_5320)

	{ 5500, 5700, 20, 6, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC },
#define	F1_5500_5700	AFTER(F1_5500_5620)
	{ 5500, 5700, 27, 0, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC | PSCAN_ETSI },
#define	F2_5500_5700	AFTER(F1_5500_5700)
	{ 5500, 5700, 30, 0, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_FCC | PSCAN_ETSI },
#define	F3_5500_5700	AFTER(F2_5500_5700)
	{ 5500, 5700, 23, 0, 20, 20, DFS_FCC3 | DFS_ETSI | DFS_MKK4, PSCAN_MKK3 | PSCAN_FCC },
#define	F4_5500_5700	AFTER(F3_5500_5700)

	{ 5745, 5805, 23, 0, 20, 20, NO_DFS, NO_PSCAN },
#define	F1_5745_5805	AFTER(F4_5500_5700)
	{ 5745, 5805, 30, 6, 20, 20, NO_DFS, NO_PSCAN },
#define	F2_5745_5805	AFTER(F1_5745_5805)
	{ 5745, 5805, 30, 6, 20, 20, DFS_ETSI, PSCAN_ETSI },
#define	F3_5745_5805	AFTER(F2_5745_5805)
	{ 5745, 5825, 5,  6, 20, 20, NO_DFS, NO_PSCAN },
#define	F1_5745_5825	AFTER(F3_5745_5805)
	{ 5745, 5825, 17, 0, 20, 20, NO_DFS, NO_PSCAN },
#define	F2_5745_5825	AFTER(F1_5745_5825)
	{ 5745, 5825, 20, 0, 20, 20, NO_DFS, NO_PSCAN },
#define	F3_5745_5825	AFTER(F2_5745_5825)
	{ 5745, 5825, 30, 0, 20, 20, NO_DFS, NO_PSCAN },
#define	F4_5745_5825	AFTER(F3_5745_5825)
	{ 5745, 5825, 30, 6, 20, 20, NO_DFS, NO_PSCAN },
#define	F5_5745_5825	AFTER(F4_5745_5825)
	{ 5745, 5825, 30, 6, 20, 20, NO_DFS, NO_PSCAN },
#define	F6_5745_5825	AFTER(F5_5745_5825)
	{ 5745, 5825, 5,  6, 10, 10, NO_DFS, NO_PSCAN },
#define	F7_5745_5825	AFTER(F6_5745_5825)
	{ 5745, 5825, 5,  6,  5,  5, NO_DFS, NO_PSCAN },
#define	F8_5745_5825	AFTER(F7_5745_5825)
	{ 5745, 5825, 30, 6, 20, 10, NO_DFS, NO_PSCAN },
#define	F9_5745_5825	AFTER(F8_5745_5825)
	{ 5745, 5825, 30, 6, 20,  5, NO_DFS, NO_PSCAN },
#define	F10_5745_5825	AFTER(F9_5745_5825)

	/*
	 * Below are the world roaming channels
	 * All WWR domains have no power limit, instead use the card's CTL
	 * or max power settings.
	 */
	{ 4920, 4980, 30, 0, 20, 20, NO_DFS, PSCAN_WWR },
#define	W1_4920_4980	AFTER(F10_5745_5825)
	{ 5040, 5080, 30, 0, 20, 20, NO_DFS, PSCAN_WWR },
#define	W1_5040_5080	AFTER(W1_4920_4980)
	{ 5170, 5230, 30, 0, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_WWR },
#define	W1_5170_5230	AFTER(W1_5040_5080)
	{ 5180, 5240, 30, 0, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_WWR },
#define	W1_5180_5240	AFTER(W1_5170_5230)
	{ 5260, 5320, 30, 0, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_WWR },
#define	W1_5260_5320	AFTER(W1_5180_5240)
	{ 5745, 5825, 30, 0, 20, 20, NO_DFS, PSCAN_WWR },
#define	W1_5745_5825	AFTER(W1_5260_5320)
	{ 5500, 5700, 30, 0, 20, 20, DFS_FCC3 | DFS_ETSI, PSCAN_WWR },
#define	W1_5500_5700	AFTER(W1_5745_5825)
	{ 5260, 5320, 30, 0, 20, 20, NO_DFS, NO_PSCAN },
#define	W2_5260_5320	AFTER(W1_5500_5700)
	{ 5180, 5240, 30, 0, 20, 20, NO_DFS, NO_PSCAN },
#define	W2_5180_5240	AFTER(W2_5260_5320)
	{ 5825, 5825, 30, 0, 20, 20, NO_DFS, PSCAN_WWR },
#define	W2_5825_5825	AFTER(W2_5180_5240)
};

/*
 * 5GHz Turbo (dynamic & static) tags
 */
static REG_DMN_FREQ_BAND regDmn5GhzTurboFreq[] = {
	{ 5130, 5210, 5,  6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_5130_5210	0
	{ 5250, 5330, 5,  6, 40, 40, DFS_FCC3, NO_PSCAN },
#define	T1_5250_5330	AFTER(T1_5130_5210)
	{ 5370, 5490, 5,  6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_5370_5490	AFTER(T1_5250_5330)
	{ 5530, 5650, 5,  6, 40, 40, DFS_FCC3, NO_PSCAN },
#define	T1_5530_5650	AFTER(T1_5370_5490)

	{ 5150, 5190, 5,  6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_5150_5190	AFTER(T1_5530_5650)
	{ 5230, 5310, 5,  6, 40, 40, DFS_FCC3, NO_PSCAN },
#define	T1_5230_5310	AFTER(T1_5150_5190)
	{ 5350, 5470, 5,  6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_5350_5470	AFTER(T1_5230_5310)
	{ 5510, 5670, 5,  6, 40, 40, DFS_FCC3, NO_PSCAN },
#define	T1_5510_5670	AFTER(T1_5350_5470)

	{ 5200, 5240, 17, 6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_5200_5240	AFTER(T1_5510_5670)
	{ 5200, 5240, 23, 6, 40, 40, NO_DFS, NO_PSCAN },
#define	T2_5200_5240	AFTER(T1_5200_5240)
	{ 5210, 5210, 17, 6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_5210_5210	AFTER(T2_5200_5240)
	{ 5210, 5210, 23, 0, 40, 40, NO_DFS, NO_PSCAN },
#define	T2_5210_5210	AFTER(T1_5210_5210)

	{ 5280, 5280, 23, 6, 40, 40, DFS_FCC3, PSCAN_FCC_T },
#define	T1_5280_5280	AFTER(T2_5210_5210)
	{ 5280, 5280, 20, 6, 40, 40, DFS_FCC3, PSCAN_FCC_T },
#define	T2_5280_5280	AFTER(T1_5280_5280)
	{ 5250, 5250, 17, 0, 40, 40, DFS_FCC3, PSCAN_FCC_T },
#define	T1_5250_5250	AFTER(T2_5280_5280)
	{ 5290, 5290, 20, 0, 40, 40, DFS_FCC3, PSCAN_FCC_T },
#define	T1_5290_5290	AFTER(T1_5250_5250)
	{ 5250, 5290, 20, 0, 40, 40, DFS_FCC3, PSCAN_FCC_T },
#define	T1_5250_5290	AFTER(T1_5290_5290)
	{ 5250, 5290, 23, 6, 40, 40, DFS_FCC3, PSCAN_FCC_T },
#define	T2_5250_5290	AFTER(T1_5250_5290)

	{ 5540, 5660, 20, 6, 40, 40, DFS_FCC3, PSCAN_FCC_T },
#define	T1_5540_5660	AFTER(T2_5250_5290)
	{ 5760, 5800, 20, 0, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_5760_5800	AFTER(T1_5540_5660)
	{ 5760, 5800, 30, 6, 40, 40, NO_DFS, NO_PSCAN },
#define	T2_5760_5800	AFTER(T1_5760_5800)

	{ 5765, 5805, 30, 6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_5765_5805	AFTER(T2_5760_5800)

	/*
	 * Below are the WWR frequencies
	 */
	{ 5210, 5250, 15, 0, 40, 40, DFS_FCC3 | DFS_ETSI, PSCAN_WWR },
#define	WT1_5210_5250	AFTER(T1_5765_5805)
	{ 5290, 5290, 18, 0, 40, 40, DFS_FCC3 | DFS_ETSI, PSCAN_WWR },
#define	WT1_5290_5290	AFTER(WT1_5210_5250)
	{ 5540, 5660, 20, 0, 40, 40, DFS_FCC3 | DFS_ETSI, PSCAN_WWR },
#define	WT1_5540_5660	AFTER(WT1_5290_5290)
	{ 5760, 5800, 20, 0, 40, 40, NO_DFS, PSCAN_WWR },
#define	WT1_5760_5800	AFTER(WT1_5540_5660)
};

/*
 * 2GHz 11b channel tags
 */
static REG_DMN_FREQ_BAND regDmn2GhzFreq[] = {
	{ 2312, 2372, 5,  6, 20, 5, NO_DFS, NO_PSCAN },
#define	F1_2312_2372	0
	{ 2312, 2372, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	F2_2312_2372	AFTER(F1_2312_2372)

	{ 2412, 2472, 5,  6, 20, 5, NO_DFS, NO_PSCAN },
#define	F1_2412_2472	AFTER(F2_2312_2372)
	{ 2412, 2472, 20, 0, 20, 5, NO_DFS, PSCAN_MKKA },
#define	F2_2412_2472	AFTER(F1_2412_2472)
	{ 2412, 2472, 30, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	F3_2412_2472	AFTER(F2_2412_2472)

	{ 2412, 2462, 27, 6, 20, 5, NO_DFS, NO_PSCAN },
#define	F1_2412_2462	AFTER(F3_2412_2472)
	{ 2412, 2462, 20, 0, 20, 5, NO_DFS, PSCAN_MKKA },
#define	F2_2412_2462	AFTER(F1_2412_2462)

	{ 2432, 2442, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	F1_2432_2442	AFTER(F2_2412_2462)

	{ 2457, 2472, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	F1_2457_2472	AFTER(F1_2432_2442)

	{ 2467, 2472, 20, 0, 20, 5, NO_DFS, PSCAN_MKKA2 | PSCAN_MKKA },
#define	F1_2467_2472	AFTER(F1_2457_2472)

	{ 2484, 2484, 5,  6, 20, 5, NO_DFS, NO_PSCAN },
#define	F1_2484_2484	AFTER(F1_2467_2472)
	{ 2484, 2484, 20, 0, 20, 5, NO_DFS, PSCAN_MKKA | PSCAN_MKKA1 | PSCAN_MKKA2 },
#define	F2_2484_2484	AFTER(F1_2484_2484)

	{ 2512, 2732, 5,  6, 20, 5, NO_DFS, NO_PSCAN },
#define	F1_2512_2732	AFTER(F2_2484_2484)

	/*
	 * WWR have powers opened up to 20dBm.
	 * Limits should often come from CTL/Max powers
	 */
	{ 2312, 2372, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	W1_2312_2372	AFTER(F1_2512_2732)
	{ 2412, 2412, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	W1_2412_2412	AFTER(W1_2312_2372)
	{ 2417, 2432, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	W1_2417_2432	AFTER(W1_2412_2412)
	{ 2437, 2442, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	W1_2437_2442	AFTER(W1_2417_2432)
	{ 2447, 2457, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	W1_2447_2457	AFTER(W1_2437_2442)
	{ 2462, 2462, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	W1_2462_2462	AFTER(W1_2447_2457)
	{ 2467, 2467, 20, 0, 20, 5, NO_DFS, PSCAN_WWR | IS_ECM_CHAN },
#define	W1_2467_2467	AFTER(W1_2462_2462)
	{ 2467, 2467, 20, 0, 20, 5, NO_DFS, NO_PSCAN | IS_ECM_CHAN },
#define	W2_2467_2467	AFTER(W1_2467_2467)
	{ 2472, 2472, 20, 0, 20, 5, NO_DFS, PSCAN_WWR | IS_ECM_CHAN },
#define	W1_2472_2472	AFTER(W2_2467_2467)
	{ 2472, 2472, 20, 0, 20, 5, NO_DFS, NO_PSCAN | IS_ECM_CHAN },
#define	W2_2472_2472	AFTER(W1_2472_2472)
	{ 2484, 2484, 20, 0, 20, 5, NO_DFS, PSCAN_WWR | IS_ECM_CHAN },
#define	W1_2484_2484	AFTER(W2_2472_2472)
	{ 2484, 2484, 20, 0, 20, 5, NO_DFS, NO_PSCAN | IS_ECM_CHAN },
#define	W2_2484_2484	AFTER(W1_2484_2484)
};

/*
 * 2GHz 11g channel tags
 */
static REG_DMN_FREQ_BAND regDmn2Ghz11gFreq[] = {
	{ 2312, 2372, 5,  6, 20, 5, NO_DFS, NO_PSCAN },
#define	G1_2312_2372	0
	{ 2312, 2372, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	G2_2312_2372	AFTER(G1_2312_2372)
	{ 2312, 2372, 5,  6, 10, 5, NO_DFS, NO_PSCAN },
#define	G3_2312_2372	AFTER(G2_2312_2372)
	{ 2312, 2372, 5,  6,  5, 5, NO_DFS, NO_PSCAN },
#define	G4_2312_2372	AFTER(G3_2312_2372)

	{ 2412, 2472, 5,  6, 20, 5, NO_DFS, NO_PSCAN },
#define	G1_2412_2472	AFTER(G4_2312_2372)
	{ 2412, 2472, 20, 0, 20, 5,  NO_DFS, PSCAN_MKKA_G },
#define	G2_2412_2472	AFTER(G1_2412_2472)
	{ 2412, 2472, 30, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	G3_2412_2472	AFTER(G2_2412_2472)
	{ 2412, 2472, 5,  6, 10, 5, NO_DFS, NO_PSCAN },
#define	G4_2412_2472	AFTER(G3_2412_2472)
	{ 2412, 2472, 5,  6,  5, 5, NO_DFS, NO_PSCAN },
#define	G5_2412_2472	AFTER(G4_2412_2472)

	{ 2412, 2462, 27, 6, 20, 5, NO_DFS, NO_PSCAN },
#define	G1_2412_2462	AFTER(G5_2412_2472)
	{ 2412, 2462, 20, 0, 20, 5, NO_DFS, PSCAN_MKKA_G },
#define	G2_2412_2462	AFTER(G1_2412_2462)
	{ 2412, 2462, 27, 6, 10, 5, NO_DFS, NO_PSCAN },
#define	G3_2412_2462	AFTER(G2_2412_2462)
	{ 2412, 2462, 27, 6,  5, 5, NO_DFS, NO_PSCAN },
#define	G4_2412_2462	AFTER(G3_2412_2462)
	
	{ 2432, 2442, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	G1_2432_2442	AFTER(G4_2412_2462)

	{ 2457, 2472, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	G1_2457_2472	AFTER(G1_2432_2442)

	{ 2512, 2732, 5,  6, 20, 5, NO_DFS, NO_PSCAN },
#define	G1_2512_2732	AFTER(G1_2457_2472)
	{ 2512, 2732, 5,  6, 10, 5, NO_DFS, NO_PSCAN },
#define	G2_2512_2732	AFTER(G1_2512_2732)
	{ 2512, 2732, 5,  6,  5, 5, NO_DFS, NO_PSCAN },
#define	G3_2512_2732	AFTER(G2_2512_2732)

	{ 2467, 2472, 20, 0, 20, 5, NO_DFS, PSCAN_MKKA2 | PSCAN_MKKA },
#define	G1_2467_2472	AFTER(G3_2512_2732)

	/*
	 * WWR open up the power to 20dBm
	 */
	{ 2312, 2372, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	WG1_2312_2372	AFTER(G1_2467_2472)
	{ 2412, 2412, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	WG1_2412_2412	AFTER(WG1_2312_2372)
	{ 2417, 2432, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	WG1_2417_2432	AFTER(WG1_2412_2412)
	{ 2437, 2442, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	WG1_2437_2442	AFTER(WG1_2417_2432)
	{ 2447, 2457, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	WG1_2447_2457	AFTER(WG1_2437_2442)
	{ 2462, 2462, 20, 0, 20, 5, NO_DFS, NO_PSCAN },
#define	WG1_2462_2462	AFTER(WG1_2447_2457)
	{ 2467, 2467, 20, 0, 20, 5, NO_DFS, PSCAN_WWR | IS_ECM_CHAN },
#define	WG1_2467_2467	AFTER(WG1_2462_2462)
	{ 2467, 2467, 20, 0, 20, 5, NO_DFS, NO_PSCAN | IS_ECM_CHAN },
#define	WG2_2467_2467	AFTER(WG1_2467_2467)
	{ 2472, 2472, 20, 0, 20, 5, NO_DFS, PSCAN_WWR | IS_ECM_CHAN },
#define	WG1_2472_2472	AFTER(WG2_2467_2467)
	{ 2472, 2472, 20, 0, 20, 5, NO_DFS, NO_PSCAN | IS_ECM_CHAN },
#define	WG2_2472_2472	AFTER(WG1_2472_2472)
};

/*
 * 2GHz Dynamic turbo tags
 */
static REG_DMN_FREQ_BAND regDmn2Ghz11gTurboFreq[] = {
	{ 2312, 2372, 5,  6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_2312_2372	0
	{ 2437, 2437, 5,  6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_2437_2437	AFTER(T1_2312_2372)
	{ 2437, 2437, 20, 6, 40, 40, NO_DFS, NO_PSCAN },
#define	T2_2437_2437	AFTER(T1_2437_2437)
	{ 2437, 2437, 18, 6, 40, 40, NO_DFS, PSCAN_WWR },
#define	T3_2437_2437	AFTER(T2_2437_2437)
	{ 2512, 2732, 5,  6, 40, 40, NO_DFS, NO_PSCAN },
#define	T1_2512_2732	AFTER(T3_2437_2437)
};

#endif
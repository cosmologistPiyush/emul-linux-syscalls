/*-
 * Copyright (c) 2014,2016 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Frank Kardel.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * IST-AG P14 calibrated Hygro-/Temperature sensor module
 * Devices: HYT-271, HYT-221 and HYT-939 
 *
 * see:
 * http://www.ist-ag.com/eh/ist-ag/resource.nsf/imgref/Download_AHHYTM_E2.1.pdf/
 *      $FILE/AHHYTM_E2.1.pdf
 */ 

/*
 * FDT direct configuration fragment to be added to i2cX definition in dtsi file
 * like in bcm2835-rpi.dtsi or another specific file.
 *
 * &i2c1 { 
 *         pinctrl-names = "default";
 *         pinctrl-0 = <&i2c1_gpio2>;
 *         status = "okay";
 *         clock-frequency = <100000>;
 *         #address-cells = <1>;
 *         #size-cells = <0>;
 *         hythygtemp@28 { 
 *                         compatible = "ist-ag,i2c-hytp14";
 *                         reg = <0x28>;
 *                         status = "okay";
 *         };
 *         hythygtemp@29 { 
 *                         compatible = "ist-ag,i2c-hytp14";
 *                         reg = <0x29>;
 *                         status = "okay";
 *         };
 * };
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: hytp14.c,v 1.15 2022/03/30 00:06:50 pgoyette Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/kthread.h>

#include <dev/sysmon/sysmonvar.h>
#include <dev/i2c/i2cvar.h>
#include <dev/i2c/hytp14reg.h>
#include <dev/i2c/hytp14var.h>

static int hytp14_match(device_t, cfdata_t, void *);
static void hytp14_attach(device_t, device_t, void *);
static int hytp14_detach(device_t, int);
static void hytp14_measurement_request(void *);
static int hytp14_refresh_sensor(struct hytp14_sc *sc);
static void hytp14_refresh(struct sysmon_envsys *, envsys_data_t *);
static void hytp14_refresh_humidity(struct hytp14_sc *, envsys_data_t *);
static void hytp14_refresh_temp(struct hytp14_sc *, envsys_data_t *);
static void hytp14_thread(void *);
static int sysctl_hytp14_interval(SYSCTLFN_ARGS);

/* #define HYT_DEBUG 3 */

#ifdef HYT_DEBUG
volatile int hythygtemp_debug = HYT_DEBUG;

#define DPRINTF(_L_, _X_) do {			\
	  if ((_L_) <= hythygtemp_debug) {	\
	    printf _X_;				\
	  }                                     \
        } while (0)
#else
#define DPRINTF(_L_, _X_)
#endif

CFATTACH_DECL_NEW(hythygtemp, sizeof(struct hytp14_sc),
    hytp14_match, hytp14_attach, hytp14_detach, NULL);

static struct hytp14_sensor hytp14_sensors[] = {
	{
		.desc = "humidity",
		.type = ENVSYS_SRELHUMIDITY,
		.refresh = hytp14_refresh_humidity
	},
	{
		.desc = "temperature",
		.type = ENVSYS_STEMP,
		.refresh = hytp14_refresh_temp
	}
};

static const struct device_compatible_entry compat_data[] = {
        { .compat = "i2c-hytp14" },
	DEVICE_COMPAT_EOL
}; 

static int
hytp14_match(device_t parent, cfdata_t match, void *aux)
{
	struct i2c_attach_args *ia = aux;
	int match_result;

	if (iic_use_direct_match(ia, match, compat_data, &match_result))
		return match_result;

	/*
	 * This device can be reprogrammed to use a different
	 * I2C address, thus checking for specific addresses 
	 * is not helpful here.
         * reprogramming is done via setting new values in
         * the device EEPROM via the hytctl utility and
	 * a special GPIO setup - see hythygtemp(4) for more
	 * information.
	 */
	return I2C_MATCH_ADDRESS_ONLY;
}

static void
hytp14_attach(device_t parent, device_t self, void *aux)
{
	const struct sysctlnode *rnode, *node;
	struct hytp14_sc *sc;
	struct i2c_attach_args *ia;
	int i, rv;

	ia = aux;
	sc = device_private(self);

	sc->sc_dev = self;
	sc->sc_tag = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;

	mutex_init(&sc->sc_mutex, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&sc->sc_condvar, "hytcv");

	sc->sc_state = HYTP14_THR_INIT;
	
	sc->sc_valid = ENVSYS_SINVALID;
	sc->sc_numsensors = __arraycount(hytp14_sensors);

	if ((sc->sc_sme = sysmon_envsys_create()) == NULL) {
		aprint_error_dev(sc->sc_dev,
		    "unable to create sysmon structure\n");
		return;
	}
	
	for (i = 0; i < sc->sc_numsensors; i++) {
		strlcpy(sc->sc_sensors[i].desc,
			hytp14_sensors[i].desc,
			sizeof sc->sc_sensors[i].desc);
		
		sc->sc_sensors[i].units = hytp14_sensors[i].type;
		sc->sc_sensors[i].state = ENVSYS_SINVALID;
		
		DPRINTF(2, ("hytp14_attach: registering sensor %d (%s)\n", i,
		    sc->sc_sensors[i].desc));
		
		if (sysmon_envsys_sensor_attach(sc->sc_sme, &sc->sc_sensors[i])) {
			aprint_error_dev(sc->sc_dev,
			    "unable to attach sensor\n");
			sysmon_envsys_destroy(sc->sc_sme);
			sc->sc_sme = NULL;
			return;
		}
	}

	sc->sc_sme->sme_name = device_xname(sc->sc_dev);
	sc->sc_sme->sme_cookie = sc;
	sc->sc_sme->sme_refresh = hytp14_refresh;

	DPRINTF(2, ("hytp14_attach: registering with envsys\n"));

	if (sysmon_envsys_register(sc->sc_sme)) {
		aprint_error_dev(sc->sc_dev,
		    "unable to register with sysmon\n");
		sysmon_envsys_destroy(sc->sc_sme);
		sc->sc_sme = NULL;
		return;
	}

	/* create a sysctl node for setting the measurement interval */
	rnode = node = NULL;
	sysctl_createv(NULL, 0, NULL, &rnode,
	    CTLFLAG_READWRITE,
	    CTLTYPE_NODE, device_xname(sc->sc_dev), NULL,
	    NULL, 0, NULL, 0,
	    CTL_HW, CTL_CREATE, CTL_EOL);

	if (rnode != NULL)
		sysctl_createv(NULL, 0, NULL, &node,
		    CTLFLAG_READWRITE | CTLFLAG_OWNDESC,
		    CTLTYPE_INT, "interval",
		    SYSCTL_DESCR("Sensor sampling interval in seconds"),
		    sysctl_hytp14_interval, 0, (void *)sc, 0,
		    CTL_HW, rnode->sysctl_num, CTL_CREATE, CTL_EOL);


	/* set up the default measurement interval for worker thread */
	sc->sc_mrinterval = HYTP14_MR_INTERVAL;

	/* create worker kthread */
	rv = kthread_create(PRI_NONE, KTHREAD_MUSTJOIN, NULL,
			    hytp14_thread, sc, &sc->sc_thread,
			    "%s", device_xname(sc->sc_dev));
	if (rv)
	  aprint_error_dev(self, "unable to create intr thread\n");

	aprint_normal(": HYT-221/271/939 humidity and temperature sensor\n");
}

static int
hytp14_detach(device_t self, int flags)
{
	struct hytp14_sc *sc;

	sc = device_private(self);

	if (sc->sc_sme != NULL)
		sysmon_envsys_unregister(sc->sc_sme);

	/* stop measurement thread */
	mutex_enter(&sc->sc_mutex);
	sc->sc_state = HYTP14_THR_STOP;
	cv_signal(&sc->sc_condvar);
	mutex_exit(&sc->sc_mutex);

	/* await thread completion */
	kthread_join(sc->sc_thread);

	/* cleanup */
	cv_destroy(&sc->sc_condvar);
	mutex_destroy(&sc->sc_mutex);
	
	return 0;
}

static void
hytp14_thread(void *aux)
{
	struct hytp14_sc *sc = aux;
	int rv;
	
	mutex_enter(&sc->sc_mutex);

	DPRINTF(2, ("%s(%s): thread start - state=%d\n",
		    __func__, device_xname(sc->sc_dev),
		    sc->sc_state));
	
	while (sc->sc_state != HYTP14_THR_STOP) {
		sc->sc_state = HYTP14_THR_RUN;

		DPRINTF(2, ("%s(%s): waiting %d seconds\n",
			    __func__, device_xname(sc->sc_dev),
				sc->sc_mrinterval));
		
		rv = cv_timedwait(&sc->sc_condvar, &sc->sc_mutex, hz * sc->sc_mrinterval);

		if (rv == EWOULDBLOCK) {
			/* timeout - run measurement */
			DPRINTF(2, ("%s(%s): timeout -> measurement\n",
				    __func__, device_xname(sc->sc_dev)));

			hytp14_measurement_request(sc);
		} else {
			DPRINTF(2, ("%s(%s): condvar signalled - state=%d\n",
				    __func__, device_xname(sc->sc_dev),
				    sc->sc_state));
		}
	}
	
	mutex_exit(&sc->sc_mutex);

	DPRINTF(2, ("%s(%s): thread exit\n",
		    __func__, device_xname(sc->sc_dev)));

	kthread_exit(0);
}

static void
hytp14_measurement_request(void *aux)
{
	uint8_t buf[I2C_EXEC_MAX_BUFLEN];
	struct hytp14_sc *sc;
	int error;

	sc = aux;
	DPRINTF(2, ("%s(%s)\n", __func__, device_xname(sc->sc_dev)));

	error = iic_acquire_bus(sc->sc_tag, 0);
	if (error == 0) {

		/* send DF command - read last data from sensor */
		error = iic_exec(sc->sc_tag, I2C_OP_READ_WITH_STOP,
		    sc->sc_addr, NULL, 0, sc->sc_data, sizeof(sc->sc_data), 0);
		if (error != 0) {
			DPRINTF(2, ("%s: %s: failed read from 0x%02x - error %d\n",
			    device_xname(sc->sc_dev), __func__,
			    sc->sc_addr, error));
			sc->sc_valid = ENVSYS_SINVALID;
		} else {
			DPRINTF(3, ("%s(%s): DF success : "
			    "0x%02x%02x%02x%02x\n",
			    __func__, device_xname(sc->sc_dev),
			    sc->sc_data[0], sc->sc_data[1],
			    sc->sc_data[2], sc->sc_data[3]));

			/* remember last data, when valid */
			if (!(sc->sc_data[0] &
			    (HYTP14_RESP_CMDMODE | HYTP14_RESP_STALE))) {
				memcpy(sc->sc_last, sc->sc_data,
				    sizeof(sc->sc_last));
				sc->sc_valid = ENVSYS_SVALID;
			}
		}

		/* send MR command to request a new measurement */
		error = iic_exec(sc->sc_tag, I2C_OP_WRITE_WITH_STOP,
		    sc->sc_addr, NULL, 0, buf, sizeof(buf), 0);

                if (error == 0) {
			DPRINTF(3, ("%s(%s): MR sent\n",
			    __func__, device_xname(sc->sc_dev)));
		} else {
			DPRINTF(2, ("%s: %s: failed read from 0x%02x - error %d\n",
			    device_xname(sc->sc_dev), __func__,
			    sc->sc_addr, error));
		}

		iic_release_bus(sc->sc_tag, 0);	
		DPRINTF(3, ("%s(%s): bus released\n",
		    __func__, device_xname(sc->sc_dev)));
	} else {
		DPRINTF(2, ("%s: %s: failed acquire i2c bus - error %d\n",
		    device_xname(sc->sc_dev), __func__, error));
	}
}

static int
hytp14_refresh_sensor(struct hytp14_sc *sc)
{
	int error;

	DPRINTF(2, ("%s(%s)\n", __func__, device_xname(sc->sc_dev)));

	error = iic_acquire_bus(sc->sc_tag, 0);
	if (error == 0) {

		/* send DF command - read last data from sensor */
		error = iic_exec(sc->sc_tag, I2C_OP_READ_WITH_STOP,
		    sc->sc_addr, NULL, 0, sc->sc_data, sizeof(sc->sc_data), 0);
		if (error != 0) {
			DPRINTF(2, ("%s: %s: failed read from 0x%02x - error %d\n",
			    device_xname(sc->sc_dev), __func__,
			    sc->sc_addr, error));
			sc->sc_valid = ENVSYS_SINVALID;
		} else {
			DPRINTF(3, ("%s(%s): DF success : "
			    "0x%02x%02x%02x%02x\n",
			    __func__, device_xname(sc->sc_dev),
			    sc->sc_data[0], sc->sc_data[1],
			    sc->sc_data[2], sc->sc_data[3]));

			/*
			 * Use old data from sc_last[] when new data
			 * is not yet valid (i.e. DF command came too
			 * quickly after the last command).
			 */
			if (!(sc->sc_data[0] &
			    (HYTP14_RESP_CMDMODE | HYTP14_RESP_STALE))) {
				memcpy(sc->sc_last, sc->sc_data,
				    sizeof(sc->sc_last));
				sc->sc_valid = ENVSYS_SVALID;
			} else
				memcpy(sc->sc_data, sc->sc_last,
				    sizeof(sc->sc_data));
		}

		iic_release_bus(sc->sc_tag, 0);	
		DPRINTF(3, ("%s(%s): bus released\n",
		    __func__, device_xname(sc->sc_dev)));
	} else {
		DPRINTF(2, ("%s: %s: failed acquire i2c bus - error %d\n",
		    device_xname(sc->sc_dev), __func__, error));
	}

	return sc->sc_valid;
}


static void
hytp14_refresh_humidity(struct hytp14_sc *sc, envsys_data_t *edata)
{
	uint16_t hyg;
	int status;
	
	status = hytp14_refresh_sensor(sc);
	
	if (status == ENVSYS_SVALID) {
		hyg = (sc->sc_data[0] << 8) | sc->sc_data[1];
		
		edata->value_cur = (1000000000 / HYTP14_HYG_SCALE) * (int32_t)HYTP14_HYG_RAWVAL(hyg);
		edata->value_cur /= 10;
	}

	edata->state = status;
}

static void
hytp14_refresh_temp(struct hytp14_sc *sc, envsys_data_t *edata)
{
	uint16_t temp;
	int status;
	
	status = hytp14_refresh_sensor(sc);
	
	if (status == ENVSYS_SVALID) {
		temp = HYTP14_TEMP_RAWVAL((sc->sc_data[2] << 8) | sc->sc_data[3]);

		edata->value_cur = (HYTP14_TEMP_FACTOR * 1000000) / HYTP14_TEMP_SCALE;
		edata->value_cur *= (int32_t)temp;
		edata->value_cur += HYTP14_TEMP_OFFSET * 1000000 + 273150000;
	}

	edata->state = status;
}

static void
hytp14_refresh(struct sysmon_envsys *sme, envsys_data_t *edata)
{
	struct hytp14_sc *sc;

	sc = sme->sme_cookie;
	hytp14_sensors[edata->sensor].refresh(sc, edata);
}

static int
sysctl_hytp14_interval(SYSCTLFN_ARGS)
{
	struct sysctlnode node;
	struct hytp14_sc *sc;
	int32_t t;
	int error;

	node = *rnode;
	sc = node.sysctl_data;

	t = sc->sc_mrinterval;
	node.sysctl_data = &t;

	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return error;
	if (t <= 0)
		return EINVAL;

	sc->sc_mrinterval = t;
	return 0;
}

MODULE(MODULE_CLASS_DRIVER, hythygtemp, "iic,sysmon_envsys");

#ifdef _MODULE
#include "ioconf.c"
#endif

static int
hythygtemp_modcmd(modcmd_t cmd, void *opaque)
{
	int error;

	error = 0;

	switch (cmd) {
	case MODULE_CMD_INIT:
#ifdef _MODULE
		error = config_init_component(cfdriver_ioconf_hythygtemp,
		    cfattach_ioconf_hythygtemp, cfdata_ioconf_hythygtemp);
#endif
		return error;

	case MODULE_CMD_FINI:
#ifdef _MODULE
		error = config_fini_component(cfdriver_ioconf_hythygtemp,
		    cfattach_ioconf_hythygtemp, cfdata_ioconf_hythygtemp);
#endif
		return error;

	default:
		return ENOTTY;
	}
}

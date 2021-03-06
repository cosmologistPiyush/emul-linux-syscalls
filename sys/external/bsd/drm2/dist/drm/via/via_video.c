/*	$NetBSD: via_video.c,v 1.8 2021/12/18 23:45:44 riastradh Exp $	*/

/*
 * Copyright 2005 Thomas Hellstrom. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sub license,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHOR(S), AND/OR THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Author: Thomas Hellstrom 2005.
 *
 * Video and XvMC related functions.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: via_video.c,v 1.8 2021/12/18 23:45:44 riastradh Exp $");

#include <drm/drm_device.h>
#include <drm/via_drm.h>

#include "via_drv.h"

void via_init_futex(drm_via_private_t *dev_priv)
{
	unsigned int i;

	DRM_DEBUG("\n");

	for (i = 0; i < VIA_NR_XVMC_LOCKS; ++i) {
#ifdef __NetBSD__
		spin_lock_init(&dev_priv->decoder_lock[i]);
		DRM_INIT_WAITQUEUE(&dev_priv->decoder_queue[i], "viadec");
#else
		init_waitqueue_head(&(dev_priv->decoder_queue[i]));
#endif
		XVMCLOCKPTR(dev_priv->sarea_priv, i)->lock = 0;
	}
}

void via_cleanup_futex(drm_via_private_t *dev_priv)
{
#ifdef __NetBSD__
	unsigned i;

	for (i = 0; i < VIA_NR_XVMC_LOCKS; ++i) {
		DRM_DESTROY_WAITQUEUE(&dev_priv->decoder_queue[i]);
		spin_lock_destroy(&dev_priv->decoder_lock[i]);
	}
#endif
}

void via_release_futex(drm_via_private_t *dev_priv, int context)
{
	unsigned int i;
	volatile int *lock;

	if (!dev_priv->sarea_priv)
		return;

	for (i = 0; i < VIA_NR_XVMC_LOCKS; ++i) {
		lock = (volatile int *)XVMCLOCKPTR(dev_priv->sarea_priv, i);
		if ((_DRM_LOCKING_CONTEXT(*lock) == context)) {
			if (_DRM_LOCK_IS_HELD(*lock)
			    && (*lock & _DRM_LOCK_CONT)) {
#ifdef __NetBSD__
				spin_lock(&dev_priv->decoder_lock[i]);
				DRM_SPIN_WAKEUP_ALL(&dev_priv->decoder_queue[i],
				    &dev_priv->decoder_lock[i]);
				spin_unlock(&dev_priv->decoder_lock[i]);
#else
				wake_up(&(dev_priv->decoder_queue[i]));
#endif
			}
			*lock = 0;
		}
	}
}

int via_decoder_futex(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	drm_via_futex_t *fx = data;
	volatile int *lock;
	drm_via_private_t *dev_priv = (drm_via_private_t *) dev->dev_private;
	drm_via_sarea_t *sAPriv = dev_priv->sarea_priv;
	int ret = 0;

	DRM_DEBUG("\n");

	if (fx->lock >= VIA_NR_XVMC_LOCKS)
		return -EFAULT;

	lock = (volatile int *)XVMCLOCKPTR(sAPriv, fx->lock);

	switch (fx->func) {
	case VIA_FUTEX_WAIT:
#ifdef __NetBSD__
		spin_lock(&dev_priv->decoder_lock[fx->lock]);
		DRM_SPIN_WAIT_ON(ret, &dev_priv->decoder_queue[fx->lock],
		    &dev_priv->decoder_lock[fx->lock],
		    (fx->ms / 10) * (HZ / 100),
		    *lock != fx->val);
		spin_unlock(&dev_priv->decoder_lock[fx->lock]);
#else
		VIA_WAIT_ON(ret, dev_priv->decoder_queue[fx->lock],
			    (fx->ms / 10) * (HZ / 100), *lock != fx->val);
#endif
		return ret;
	case VIA_FUTEX_WAKE:
#ifdef __NetBSD__
		spin_lock(&dev_priv->decoder_lock[fx->lock]);
		DRM_SPIN_WAKEUP_ALL(&dev_priv->decoder_queue[fx->lock],
		    &dev_priv->decoder_lock[fx->lock]);
		spin_unlock(&dev_priv->decoder_lock[fx->lock]);
#else
		wake_up(&(dev_priv->decoder_queue[fx->lock]));
#endif
		return 0;
	}
	return 0;
}

/*	$NetBSD: debugfs_engines.c,v 1.2 2021/12/18 23:45:30 riastradh Exp $	*/

// SPDX-License-Identifier: MIT

/*
 * Copyright © 2019 Intel Corporation
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: debugfs_engines.c,v 1.2 2021/12/18 23:45:30 riastradh Exp $");

#include <drm/drm_print.h>

#include "debugfs_engines.h"
#include "debugfs_gt.h"
#include "i915_drv.h" /* for_each_engine! */
#include "intel_engine.h"

static int engines_show(struct seq_file *m, void *data)
{
	struct intel_gt *gt = m->private;
	struct intel_engine_cs *engine;
	enum intel_engine_id id;
	struct drm_printer p;

	p = drm_seq_file_printer(m);
	for_each_engine(engine, gt, id)
		intel_engine_dump(engine, &p, "%s\n", engine->name);

	return 0;
}
DEFINE_GT_DEBUGFS_ATTRIBUTE(engines);

void debugfs_engines_register(struct intel_gt *gt, struct dentry *root)
{
	static const struct debugfs_gt_file files[] = {
		{ "engines", &engines_fops },
	};

	debugfs_gt_register_files(gt, root, files, ARRAY_SIZE(files));
}

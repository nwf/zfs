/*
 * Bring up enough of ZFS to write an integer into a ZAP object on a
 * synthetic pool, or read said integer back.  That has to be really simple,
 * right?
 *
 * One may wish to run this with ZFS_DEBUG=on and possibly have compiled
 * with ./configure --enable-debug for even more verbosity and, if even more
 * is desired, modifying dsl_scan.c to dump its block pointers
 */

#include <stdio.h>
#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/dmu_objset.h>
#include <sys/spa_impl.h>
#include <sys/dsl_scan.h>
#include <libnvpair.h>

const char *a_pool_name = "atest-pool";

enum ztest_object_id {
  ZTID_META_DNODE = 0,	// XXX this appears to be a zfs-internal thing
  ZTID_TESTOBJ,			// This one is ours.
  ZTID_OBJECTS
};

void
objset_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	/* We don't *have* to do this here, but it's convenient since we have
     * the os handle.
     */ 
	VERIFY3U(0,==,zap_create_claim(os, ZTID_TESTOBJ, DMU_OT_ZAP_OTHER, DMU_OT_NONE, 0, tx));
}

int
main(int argc, char **argv)
{
	int do_create = 0, do_scrub = 0;
	spa_t *spa;
	objset_t *os;

	{
		int opt;
    	while ((opt = getopt(argc, argv, "cs")) != EOF) {
			switch(opt){
			case 'c':
				do_create++;
				break;
			case 's':
				do_scrub++;
				break;
			}
		}
    }

	VERIFY(asprintf((char **)&spa_config_path, "/tmp/atest-zpool.cache"));

	dprintf_setup(&argc, argv);
	kernel_init(FREAD | FWRITE);

	{
		int err;
    	nvlist_t *root, *child;
		const char *path = "/tmp/atest-vdev"; 

		if (do_create) {
			int vdevfd;
			unlink(path);
			vdevfd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0666);
	    	ASSERT3S(vdevfd, >=, 0);
			VERIFY3S(0,==,ftruncate(vdevfd, 128*1024*1024));
			close(vdevfd);
		}

		VERIFY(nvlist_alloc(&child, NV_UNIQUE_NAME, 0) == 0);
		VERIFY(nvlist_add_string(child, ZPOOL_CONFIG_TYPE, VDEV_TYPE_FILE) == 0);
		VERIFY(nvlist_add_string(child, ZPOOL_CONFIG_PATH, path) == 0);
		VERIFY(nvlist_add_uint64(child, ZPOOL_CONFIG_ASHIFT, 12) == 0);

		VERIFY(nvlist_alloc(&root, NV_UNIQUE_NAME, 0) == 0);
		VERIFY(nvlist_add_string(root, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT) == 0);
		VERIFY(nvlist_add_nvlist_array(root, ZPOOL_CONFIG_CHILDREN, &child, 1) == 0);

		nvlist_free(child);

		// XXX there must be a better way to introduce the vdevs to the spa
		// layer than to try to create and let it fail when we're not
		// creating.  Either way, this seems to populate whatever cache
		// exists inside ZFS's mind.

	    err = spa_create(a_pool_name, root, NULL, NULL, NULL);
		ASSERT((err == 0) || !do_create);
	    nvlist_free(root);
	}

	VERIFY3U(0,==,spa_open(a_pool_name, &spa, FTAG));
	spa->spa_debug = B_TRUE;

	// Have spa, will travel; either make or find a dataset for our use

	{
		char *a_dataset_name;
		VERIFY(asprintf((char **)&a_dataset_name, "%s/a", a_pool_name));
		if(do_create) {
			VERIFY3U(0,==,dmu_objset_create(a_dataset_name, DMU_OST_OTHER, 0, NULL, objset_create_cb, NULL));
		}
		VERIFY0(dmu_objset_own(a_dataset_name, DMU_OST_OTHER, B_FALSE, B_FALSE, FTAG, &os));
	}

	// Alright, the dataset's all set up and we've got a handle to it in os;
	// let's use that zap we created above.

	{
		dmu_tx_t *tx;
		uint64_t v;

		if(do_create) {
			// Stash a key in the zap, transactionally.
			v = 0xABCDEF4215410DE0ULL;
			tx = dmu_tx_create(os);
			dmu_tx_hold_zap(tx, ZTID_TESTOBJ, B_TRUE, NULL);
			VERIFY0(dmu_tx_assign(tx, TXG_WAIT));
			VERIFY3U(0,==,zap_add(os, ZTID_TESTOBJ, "key", sizeof (v), 1, &v, tx));
			dmu_tx_commit(tx);
		} else {
			// Retrieve the stash from last time, and increment it.
			tx = dmu_tx_create(os);
			dmu_tx_hold_zap(tx, ZTID_TESTOBJ, B_TRUE, NULL);
			VERIFY0(dmu_tx_assign(tx, TXG_WAIT));
			VERIFY3U(0,==,zap_lookup(os, ZTID_TESTOBJ, "key", sizeof (v), 1, &v));
			v++;
			VERIFY3U(0,==,zap_update(os, ZTID_TESTOBJ, "key", sizeof (v), 1, &v, tx));
			dmu_tx_commit(tx);

			fprintf(stderr,"Key is now: %lx\n", v);
		}
	}

	// Kick off a scrub?
	if (do_scrub) {
        fprintf(stderr, "Kicking off scrub...\n");
		spa_scan(spa, POOL_SCAN_SCRUB);
        while(spa->spa_dsl_pool->dp_scan->scn_phys.scn_state != DSS_FINISHED) {
			fprintf(stderr, "Scrub scan state = %lu\n", spa->spa_dsl_pool->dp_scan->scn_phys.scn_state);
			sleep(1);
		}
	}

	// Drop the reference to the object set
	dmu_objset_disown(os, B_FALSE, FTAG);
	// and the pool
	spa_close(spa, FTAG);
	// and everything else
	kernel_fini();

	return 0;
}

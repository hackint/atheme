/* groupserv - group services.
 * Copyright (c) 2010 Atheme Development Group
 */

#include "groupserv_main.h"

#define GDBV_VERSION	4

static unsigned int loading_gdbv = -1;
static unsigned int their_ga_all;

static void write_groupdb(database_handle_t *db)
{
	myentity_t *mt;
	myentity_iteration_state_t state;
	mowgli_patricia_iteration_state_t state2;
	metadata_t *md;

	db_start_row(db, "GDBV");
	db_write_uint(db, GDBV_VERSION);
	db_commit_row(db);

	db_start_row(db, "GFA");
	db_write_word(db, gflags_tostr(ga_flags, GA_ALL));
	db_commit_row(db);

	MYENTITY_FOREACH_T(mt, &state, ENT_GROUP)
	{
		mowgli_node_t *n;

		continue_if_fail(mt != NULL);
		mygroup_t *mg = group(mt);
		continue_if_fail(mg != NULL);

		char *mgflags = gflags_tostr(mg_flags, mg->flags);

		db_start_row(db, "GRP");
		db_write_word(db, entity(mg)->id);
		db_write_word(db, entity(mg)->name);
		db_write_time(db, mg->regtime);
		db_write_word(db, mgflags);
		db_commit_row(db);

		MOWGLI_ITER_FOREACH(n, mg->acs.head)
		{
			groupacs_t *ga = n->data;
			char *flags = gflags_tostr(ga_flags, ga->flags);

			db_start_row(db, "GACL");
			db_start_row(db, entity(mg)->name);
			db_start_row(db, ga->mt->name);
			db_start_row(db, flags);
			db_commit_row(db);
		}

		if (object(mg)->metadata)
		{
			MOWGLI_PATRICIA_FOREACH(md, &state2, object(mg)->metadata)
			{
				db_start_row(db, "MDG");
				db_write_word(db, entity(mg)->name);
				db_write_word(db, md->name);
				db_write_str(db, md->value);
				db_commit_row(db);
			}
		}
	}

	mowgli_node_t *n;

	MOWGLI_ITER_FOREACH(n, gs_invitelist.head)
	{
		gsinvite_t *l = n->data;

		db_start_row(db, "GRPI");

		if (l->mg != NULL)
			db_write_word(db, entity(l->mg)->name);
		if (l->mt != NULL)
			db_write_word(db, l->mt->name);

		db_write_word(db, l->inviter);
		db_write_time(db, l->invitets);
		db_commit_row(db);
	}
}

static void db_h_gdbv(database_handle_t *db, const char *type)
{
	loading_gdbv = db_sread_uint(db);
	slog(LG_INFO, "groupserv: opensex data schema version is %d.", loading_gdbv);

	their_ga_all = GA_ALL_OLD;
}

static void db_h_gfa(database_handle_t *db, const char *type)
{
	const char *flags = db_sread_word(db);

	gflags_fromstr(ga_flags, flags, &their_ga_all);
	if (their_ga_all & ~GA_ALL)
	{
		slog(LG_ERROR, "db-h-gfa: losing flags %s from file", gflags_tostr(ga_flags, their_ga_all & ~GA_ALL));
	}
	if (~their_ga_all & GA_ALL)
	{
		slog(LG_ERROR, "db-h-gfa: making up flags %s not present in file", gflags_tostr(ga_flags, ~their_ga_all & GA_ALL));
	}
}

static void db_h_grp(database_handle_t *db, const char *type)
{
	mygroup_t *mg;
	const char *uid = NULL;
	const char *name;
	time_t regtime;
	const char *flagset;

	if (loading_gdbv >= 4)
		uid = db_sread_word(db);

	name = db_sread_word(db);

	if (mygroup_find(name))
	{
		slog(LG_INFO, "db-h-grp: line %d: skipping duplicate group %s", db->line, name);
		return;
	}
	if (uid && myentity_find_uid(uid))
	{
		slog(LG_INFO, "db-h-grp: line %d: skipping group %s with duplicate UID %s", db->line, name, uid);
		return;
	}

	regtime = db_sread_time(db);

	mg = mygroup_add_id(uid, name);
	mg->regtime = regtime;

	if (loading_gdbv >= 3)
	{
		flagset = db_sread_word(db);

		if (!gflags_fromstr(mg_flags, flagset, &mg->flags))
			slog(LG_INFO, "db-h-grp: line %d: confused by flags: %s", db->line, flagset);
	}
}

static void db_h_gacl(database_handle_t *db, const char *type)
{
	mygroup_t *mg;
	myentity_t *mt;
	unsigned int flags = GA_ALL;	/* GDBV 1 entires had full access */

	const char *name = db_sread_word(db);
	const char *entity = db_sread_word(db);
	const char *flagset;

	mg = mygroup_find(name);
	mt = myentity_find(entity);

	if (mg == NULL)
	{
		slog(LG_INFO, "db-h-gacl: line %d: groupacs for nonexistent group %s", db->line, name);
		return;
	}

	if (mt == NULL)
	{
		slog(LG_INFO, "db-h-gacl: line %d: groupacs for nonexistent entity %s", db->line, entity);
		return;
	}

	if (loading_gdbv >= 2)
	{
		flagset = db_sread_word(db);

		if (!gflags_fromstr(ga_flags, flagset, &flags))
			slog(LG_INFO, "db-h-gacl: line %d: confused by flags: %s", db->line, flagset);

		/* ACL view permission was added, so make up the permission (#279), but only if the database
		 * is from atheme 7.1 or earlier. --kaniini
		 */
		if (!(their_ga_all & GA_ACLVIEW) && ((flags & GA_ALL_OLD) == their_ga_all))
			flags |= GA_ACLVIEW;
	}

	groupacs_add(mg, mt, flags);
}

static void db_h_mdg(database_handle_t *db, const char *type)
{
	const char *name = db_sread_word(db);
	const char *prop = db_sread_word(db);
	const char *value = db_sread_str(db);
	void *obj = NULL;

	obj = mygroup_find(name);

	if (obj == NULL)
	{
		slog(LG_INFO, "db-h-mdg: attempting to add %s property to non-existant object %s",
		     prop, name);
		return;
	}

	metadata_add(obj, prop, value);
}

static void db_h_grpi(database_handle_t *db, const char *type)
{
	mygroup_t *mg;
	myentity_t *mt;
	const char *group = db_sread_word(db);
	const char *entity = db_sread_word(db);
	const char *inviter = db_sread_word(db);
	time_t invitets = db_sread_time(db);

	mg = mygroup_find(group);
	mt = myentity_find(entity);
	mt = myentity_find(entity);

	if (mt == NULL)
	{
		slog(LG_INFO, "db-h-grpi: line %d: groupinvite for nonexistent entity %s", db->line, entity);
		return;
	}

	if (mg == NULL)
	{
		slog(LG_INFO, "db-h-grpi: line %d: groupinvite for nonexistent group %s", db->line, group);
		return;
	}

	add_gs_invite(mg, mt, strshare_get(inviter), invitets);
}

gsinvite_t *gs_invite_find(mygroup_t *mg, myentity_t *mt)
{
	mowgli_node_t *n;
	gsinvite_t *l;

	MOWGLI_ITER_FOREACH(n, gs_invitelist.head)
	{
		l = n->data;

		if ((l->mg == mg || mg == NULL) && (l->mt == mt || mt == NULL))
			return l;
	}

	return NULL;
}

void remove_gs_invite(mygroup_t *mg, myentity_t *mt)
{
	return_if_fail(mg != NULL);
	return_if_fail(mt != NULL);

	mowgli_node_t *n, *tn;
	gsinvite_t *l;

	MOWGLI_ITER_FOREACH_SAFE(n, tn, gs_invitelist.head)
	{
		l = n->data;

		if ((l->mg != NULL && l->mg == mg) && (l->mt != NULL && l->mt == mt))
		{
			slog(LG_VERBOSE, "remove_gs_invite(): removing invite for %s (group %s)", l->mt->name, entity(l->mg)->name);

			mowgli_node_delete(n, &gs_invitelist);

			strshare_unref(l->inviter);
			free(l);
		}
	}
}

int add_gs_invite(mygroup_t *mg, myentity_t *mt, const char *inviter, time_t invitets)
{
	return_val_if_fail(mg != NULL, -1);
	return_val_if_fail(mt != NULL, -1);

	gsinvite_t *l;

	l = gs_invite_find(mg, mt);
	if (l != NULL)
	{
		// Alrady invited
		return 0;
	}

	l = smalloc(sizeof(gsinvite_t));

	l->mg = mg;
	l->mt = mt;
	l->invitets = invitets;
	l->inviter = inviter;
	mowgli_node_add(l, &l->node, &gs_invitelist);

	return 1;
}

mowgli_list_t gs_get_invitelist()
{
	return gs_invitelist;
}

void gs_db_init(void)
{
	hook_add_db_write_pre_ca(write_groupdb);

	db_register_type_handler("GDBV", db_h_gdbv);
	db_register_type_handler("GRP", db_h_grp);
	db_register_type_handler("GACL", db_h_gacl);
	db_register_type_handler("MDG", db_h_mdg);
	db_register_type_handler("GFA", db_h_gfa);
	db_register_type_handler("GRPI", db_h_grpi);
}

void gs_db_deinit(void)
{
	hook_del_db_write_pre_ca(write_groupdb);

	db_unregister_type_handler("GDBV");
	db_unregister_type_handler("GRP");
	db_unregister_type_handler("GACL");
	db_unregister_type_handler("MDG");
	db_unregister_type_handler("GFA");
	db_unregister_type_handler("GRPI");
}

/* groupserv - group services.
 * Copyright (C) 2010 Atheme Development Group
 */

#include "groupserv_main.h"

static void mygroup_expire(void *unused)
{
	myentity_t *mt;
	myentity_iteration_state_t state;

	MYENTITY_FOREACH_T(mt, &state, ENT_GROUP)
	{
		mygroup_t *mg = group(mt);

		continue_if_fail(mt != NULL);
		continue_if_fail(mg != NULL);

		if (!mygroup_count_flag(mg, GA_FOUNDER))
		{
			remove_group_chanacs(mg);
			object_unref(mg);
		}
	}
}

static void grant_channel_access_hook(user_t *u)
{
	mowgli_node_t *n, *tn;
	mowgli_list_t *l;

	return_if_fail(u->myuser != NULL);

	l = myentity_get_membership_list(entity(u->myuser));

	MOWGLI_ITER_FOREACH_SAFE(n, tn, l->head)
	{
		groupacs_t *ga = n->data;

		if (!(ga->flags & GA_CHANACS))
			continue;

		MOWGLI_ITER_FOREACH(n, entity(ga->mg)->chanacs.head)
		{
			chanacs_t *ca;
			chanuser_t *cu;

			ca = (chanacs_t *)n->data;

			if (ca->mychan->chan == NULL)
				continue;

			cu = chanuser_find(ca->mychan->chan, u);
			if (cu && chansvs.me != NULL)
			{
				if (ca->level & CA_AKICK && !(ca->level & CA_EXEMPT))
				{
					/* Stay on channel if this would empty it -- jilles */
					if (ca->mychan->chan->nummembers - ca->mychan->chan->numsvcmembers == 1)
					{
						ca->mychan->flags |= MC_INHABIT;
						if (ca->mychan->chan->numsvcmembers == 0)
							join(cu->chan->name, chansvs.nick);
					}
					ban(chansvs.me->me, ca->mychan->chan, u);
					remove_ban_exceptions(chansvs.me->me, ca->mychan->chan, u);
					kick(chansvs.me->me, ca->mychan->chan, u, "User is banned from this channel");
					continue;
				}

				if (ca->level & CA_USEDUPDATE)
					ca->mychan->used = CURRTIME;

				if (ca->mychan->flags & MC_NOOP || u->myuser->flags & MU_NOOP)
					continue;

				if (ircd->uses_owner && !(cu->modes & ircd->owner_mode) && ca->level & CA_AUTOOP && ca->level & CA_USEOWNER)
				{
					modestack_mode_param(chansvs.nick, ca->mychan->chan, MTYPE_ADD, ircd->owner_mchar[1], CLIENT_NAME(u));
					cu->modes |= ircd->owner_mode;
				}

				if (ircd->uses_protect && !(cu->modes & ircd->protect_mode) && !(ircd->uses_owner && cu->modes & ircd->owner_mode) && ca->level & CA_AUTOOP && ca->level & CA_USEPROTECT)
				{
					modestack_mode_param(chansvs.nick, ca->mychan->chan, MTYPE_ADD, ircd->protect_mchar[1], CLIENT_NAME(u));
					cu->modes |= ircd->protect_mode;
				}

				if (!(cu->modes & CSTATUS_OP) && ca->level & CA_AUTOOP)
				{
					modestack_mode_param(chansvs.nick, ca->mychan->chan, MTYPE_ADD, 'o', CLIENT_NAME(u));
					cu->modes |= CSTATUS_OP;
				}

				if (ircd->uses_halfops && !(cu->modes & (CSTATUS_OP | ircd->halfops_mode)) && ca->level & CA_AUTOHALFOP)
				{
					modestack_mode_param(chansvs.nick, ca->mychan->chan, MTYPE_ADD, 'h', CLIENT_NAME(u));
					cu->modes |= ircd->halfops_mode;
				}

				if (!(cu->modes & (CSTATUS_OP | ircd->halfops_mode | CSTATUS_VOICE)) && ca->level & CA_AUTOVOICE)
				{
					modestack_mode_param(chansvs.nick, ca->mychan->chan, MTYPE_ADD, 'v', CLIENT_NAME(u));
					cu->modes |= CSTATUS_VOICE;
				}
			}
		}
	}
}

static void user_info_hook(hook_user_req_t *req)
{
	static char buf[BUFSIZE];
	mowgli_node_t *n;
	mowgli_list_t *l;

	*buf = 0;

	l = myentity_get_membership_list(entity(req->mu));

	MOWGLI_ITER_FOREACH(n, l->head)
	{
		groupacs_t *ga = n->data;

		if (ga->flags & GA_BAN)
			continue;

		if ((ga->mg->flags & MG_PUBLIC) || (req->si->smu == req->mu || has_priv(req->si, PRIV_GROUP_AUSPEX)))
		{
			if (*buf != 0)
				mowgli_strlcat(buf, ", ", BUFSIZE);

			mowgli_strlcat(buf, entity(ga->mg)->name, BUFSIZE);
		}
	}

	if (*buf != 0)
		command_success_nodata(req->si, _("Groups     : %s"), buf);
}

static void sasl_may_impersonate_hook(hook_sasl_may_impersonate_t *req)
{
	char priv[BUFSIZE];
	mowgli_list_t *l;
	mowgli_node_t *n;

	/* if the request is already granted, don't bother doing any of this. */
	if (req->allowed)
		return;

	l = myentity_get_membership_list(entity(req->target_mu));

	MOWGLI_ITER_FOREACH(n, l->head)
	{
		groupacs_t *ga = n->data;

		snprintf(priv, sizeof(priv), PRIV_IMPERSONATE_ENTITY_FMT, entity(ga->mg)->name);

		if (has_priv_myuser(req->source_mu, priv))
		{
			req->allowed = true;
			return;
		}
	}
}

static void myuser_delete_hook(myuser_t *mu)
{
	mowgli_node_t *n, *tn;
	mowgli_list_t *l;
	hook_group_user_delete_t hdata;
	myentity_iteration_state_t state;
	myentity_t *mt;
	mygroup_t *mg;
	groupinvite_t *gi;

	l = myentity_get_membership_list(entity(mu));

	MOWGLI_ITER_FOREACH_SAFE(n, tn, l->head)
	{
		groupacs_t *ga = n->data;

		hdata.mu = mu;
		hdata.mg = ga->mg;
		hook_call_group_user_delete(&hdata);

		groupacs_delete(ga->mg, ga->mt);
	}

	mowgli_list_free(l);

	MYENTITY_FOREACH_T(mt, &state, ENT_GROUP)
	{
		mg = group(mt);
		continue_if_fail(mt != NULL);
		continue_if_fail(mg != NULL);

		MOWGLI_ITER_FOREACH(n, mg->invites.head)
		{
			gi = n->data;

			if (gi->mg == mg && gi->mt == entity(mu) || gi->mg == mg && gi->inviter == entity(mu)->name) {
				slog(LG_REGISTER, _("GRPI: Deleting invite for \2%s\2 from \2%s\2 for group \2%s\2"), gi->mt->name, gi->inviter, entity(gi->mg)->name);
				groupinvite_delete(mg, gi->mt);
			}
		}
	}
}

static void group_user_delete(hook_group_user_delete_t *hdata)
{
	myuser_t *successor;
	myuser_t *mu;
	mygroup_t *mg;
	groupacs_t *ga;
	unsigned int flags = 0;
	mowgli_node_t *n;
	groupinvite_t *gi;

	mu = hdata->mu;
	mg = hdata->mg;

	/* not a founder */
	if(!groupacs_find(mg, entity(mu), GA_FOUNDER, false))
		return;

	/* other founders remaining */
	if (mygroup_count_flag(mg, GA_FOUNDER) > 1)
		return;

	if ((successor = mygroup_pick_successor(mg)) != NULL)
	{

		slog(LG_INFO, "group_user_delete: !!!4");
		slog(LG_INFO, _("SUCCESSION: \2%s\2 to \2%s\2 from \2%s\2"), entity(mg)->name, entity(successor)->name, mygroup_founder_names(mg));
		slog(LG_VERBOSE, "group_user_delete(): giving group %s to %s (founder %s)",
				entity(mg)->name, entity(successor)->name,
				mygroup_founder_names(mg));

		MOWGLI_ITER_FOREACH(n, mg->invites.head)
		{
			gi = n->data;
			if (gi->mg == mg && gi->inviter == entity(mu)->name) {
				slog(LG_INFO, _("GRPI: Changing inviter from \2%s\2 to \2%s\2 (invite for \2%s\2 to group \2%s\2)"), mygroup_founder_names(mg),
					entity(successor)->name, gi->mt->name, entity(mg)->name);
					gi->inviter = strshare_ref(entity(successor)->name);
			}
		}

		ga = groupacs_find(mg, entity(successor), 0, false);
		if (ga != NULL) {
			flags = ga->flags;
			flags = gs_flags_parser("+F*", 1, flags);
			ga->flags = flags;
		}

		if (groupsvs->me != NULL)
			myuser_notice(groupsvs->nick, successor, "You are now founder of group \2%s\2 (as \2%s\2).", entity(mg)->name, entity(successor)->name);
	}
	/* no successor found */
	else
	{
		slog(LG_REGISTER, _("DELETE: \2%s\2 from \2%s\2"), entity(mg)->name, mygroup_founder_names(mg));
		slog(LG_VERBOSE, "group_user_delete(): deleting group %s (founder %s)",
				entity(mg)->name, mygroup_founder_names(mg));

		remove_group_chanacs(mg);
		hook_call_group_drop(mg);
		object_unref(mg);
	}
}

static void osinfo_hook(sourceinfo_t *si)
{
	return_if_fail(si != NULL);

	command_success_nodata(si, "Maximum number of groups one user can own: %u", gs_config.maxgroups);
	command_success_nodata(si, "Maximum number of ACL entries allowed for one group: %u", gs_config.maxgroupacs);
	command_success_nodata(si, "Are open groups allowed: %s", gs_config.enable_open_groups ? "Yes" : "No");
	command_success_nodata(si, "Default joinflags for open groups: %s", gs_config.join_flags);
}

static mowgli_eventloop_timer_t *mygroup_expire_timer = NULL;

void gs_hooks_init(void)
{
	mygroup_expire_timer = mowgli_timer_add(base_eventloop, "mygroup_expire", mygroup_expire, NULL, 3600);

	hook_add_event("myuser_delete");
	hook_add_event("user_info");
	hook_add_event("grant_channel_access");
	hook_add_event("operserv_info");
	hook_add_event("sasl_may_impersonate");
	hook_add_event("group_user_delete");

	hook_add_user_info(user_info_hook);
	hook_add_myuser_delete(myuser_delete_hook);
	hook_add_grant_channel_access(grant_channel_access_hook);
	hook_add_operserv_info(osinfo_hook);
	hook_add_sasl_may_impersonate(sasl_may_impersonate_hook);
	hook_add_group_user_delete(group_user_delete);
}

void gs_hooks_deinit(void)
{
	mowgli_timer_destroy(base_eventloop, mygroup_expire_timer);

	hook_del_user_info(user_info_hook);
	hook_del_myuser_delete(myuser_delete_hook);
	hook_del_grant_channel_access(grant_channel_access_hook);
	hook_del_operserv_info(osinfo_hook);
	hook_del_sasl_may_impersonate(sasl_may_impersonate_hook);
	hook_del_group_user_delete(group_user_delete);
}

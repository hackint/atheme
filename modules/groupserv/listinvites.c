/*
 * Copyright (c) 2005 Atheme Development Group
 * Rights to this code are documented in doc/LICENSE.
 *
 * This file contains routines to handle the GroupServ HELP command.
 *
 */

#include "atheme.h"
#include "groupserv.h"

DECLARE_MODULE_V1
(
	"groupserv/listinvites", false, _modinit, _moddeinit,
	PACKAGE_STRING,
	"Shaltúre developers <https://github.com/shalture>"
);

static void gs_cmd_listinvites(sourceinfo_t *si, int parc, char *parv[]);

command_t gs_listinvites = { "LISTINVITES", N_("List groups with pending invitations."), AC_AUTHENTICATED, 2, gs_cmd_listinvites, { .path = "groupserv/listinvites" } };

/* Perhaps add criteria to groupser/list like there is now in chanserv/list and nickserv/list in the future */
static void gs_cmd_listinvites(sourceinfo_t *si, int parc, char *parv[])
{
	gsinvite_t *l;
	mowgli_node_t *n;
	char buf[BUFSIZE];
	struct tm tm;
	mowgli_list_t gs_invitelist;

	/* No need to say "Groups currently registered". You can't have a unregistered group. */
	command_success_nodata(si, _("Groups you are invited to:"));

	gs_invitelist = gs_get_invitelist();
	MOWGLI_ITER_FOREACH(n, gs_invitelist.head)
	{
		l = n->data;
		if (l->mt != entity(si->smu) || entity(si->smu) == NULL)
			continue;

		tm = *localtime(&l->invitets);

		strftime(buf, BUFSIZE, TIME_FORMAT, &tm);

		command_success_nodata(si, "group:\2%s\2 inviter:\2%s\2 (%s)",
					entity(l->mg)->name, l->inviter, buf);
	}
	command_success_nodata(si, "End of list.");
	logcommand(si, CMDLOG_GET, "LISTINVITES");

}

void _modinit(module_t *m)
{
	use_groupserv_main_symbols(m);

	service_named_bind_command("groupserv", &gs_listinvites);
}

void _moddeinit(module_unload_intent_t intent)
{
	service_named_unbind_command("groupserv", &gs_listinvites);
}

/* groupserv.h - group services public interface
 *
 * Include this header for modules other than groupserv/main
 * that need to access group functionality.
 *
 * Copyright (C) 2010 Atheme Development Group
 */

#ifndef GROUPSERV_H
#define GROUPSERV_H

#include "main/groupserv_common.h"

mygroup_t * (*mygroup_add)(const char *name);
mygroup_t * (*mygroup_find)(const char *name);
mygroup_t * (*mygroup_rename)(mygroup_t *mg, const char *name);

unsigned int (*mygroup_count_flag)(mygroup_t *mg, unsigned int flag);
unsigned int (*myentity_count_group_flag)(myentity_t *mu, unsigned int flagset);

groupacs_t * (*groupacs_add)(mygroup_t *mg, myentity_t *mt, unsigned int flags);
groupacs_t * (*groupacs_find)(mygroup_t *mg, myentity_t *mt, unsigned int flags, bool allow_recurse);
void (*groupacs_delete)(mygroup_t *mg, myentity_t *mt);

bool (*groupacs_sourceinfo_has_flag)(mygroup_t *mg, sourceinfo_t *si, unsigned int flag);
unsigned int (*groupacs_sourceinfo_flags)(mygroup_t *mg, sourceinfo_t *si);
unsigned int (*gs_flags_parser)(char *flagstring, int allow_minus, unsigned int flags);
mowgli_list_t * (*myentity_get_membership_list)(myentity_t *mu);
const char * (*mygroup_founder_names)(mygroup_t *mg);
void (*remove_group_chanacs)(mygroup_t *mg);

gflags_t *ga_flags;

groupserv_config_t *gs_config;

gsinvite_t * (*gs_invite_find)(mygroup_t *mg, myentity_t *mt);
void (*remove_gs_invite)(mygroup_t *mg, myentity_t *mt);
int (*add_gs_invite)(mygroup_t *mg, myentity_t *mt, const char *inviter, time_t invitets);
mowgli_list_t (*gs_get_invitelist)(void);

static inline void use_groupserv_main_symbols(module_t *m)
{
    MODULE_TRY_REQUEST_DEPENDENCY(m, "groupserv/main");
    MODULE_TRY_REQUEST_SYMBOL(m, mygroup_add, "groupserv/main", "mygroup_add");
    MODULE_TRY_REQUEST_SYMBOL(m, mygroup_find, "groupserv/main", "mygroup_find");
    MODULE_TRY_REQUEST_SYMBOL(m, mygroup_rename, "groupserv/main", "mygroup_rename");
    MODULE_TRY_REQUEST_SYMBOL(m, mygroup_count_flag, "groupserv/main", "mygroup_count_flag");
    MODULE_TRY_REQUEST_SYMBOL(m, myentity_count_group_flag, "groupserv/main", "myentity_count_group_flag");
    MODULE_TRY_REQUEST_SYMBOL(m, groupacs_add, "groupserv/main", "groupacs_add");
    MODULE_TRY_REQUEST_SYMBOL(m, groupacs_find, "groupserv/main", "groupacs_find");
    MODULE_TRY_REQUEST_SYMBOL(m, groupacs_delete, "groupserv/main", "groupacs_delete");
    MODULE_TRY_REQUEST_SYMBOL(m, groupacs_sourceinfo_has_flag, "groupserv/main", "groupacs_sourceinfo_has_flag");
    MODULE_TRY_REQUEST_SYMBOL(m, groupacs_sourceinfo_flags, "groupserv/main", "groupacs_sourceinfo_flags");

    MODULE_TRY_REQUEST_SYMBOL(m, gs_flags_parser, "groupserv/main", "gs_flags_parser");
    MODULE_TRY_REQUEST_SYMBOL(m, myentity_get_membership_list, "groupserv/main", "myentity_get_membership_list");
    MODULE_TRY_REQUEST_SYMBOL(m, mygroup_founder_names, "groupserv/main", "mygroup_founder_names");
    MODULE_TRY_REQUEST_SYMBOL(m, remove_group_chanacs, "groupserv/main", "remove_group_chanacs");

    MODULE_TRY_REQUEST_SYMBOL(m, ga_flags, "groupserv/main", "ga_flags");
    MODULE_TRY_REQUEST_SYMBOL(m, gs_config, "groupserv/main", "gs_config");

    MODULE_TRY_REQUEST_SYMBOL(m, gs_invite_find, "groupserv/main", "gs_invite_find");
    MODULE_TRY_REQUEST_SYMBOL(m, remove_gs_invite, "groupserv/main", "remove_gs_invite");
    MODULE_TRY_REQUEST_SYMBOL(m, add_gs_invite, "groupserv/main", "add_gs_invite");
    MODULE_TRY_REQUEST_SYMBOL(m, gs_get_invitelist, "groupserv/main", "gs_get_invitelist");
}

#ifndef IN_GROUPSERV_SET

mowgli_patricia_t *gs_set_cmdtree;

static inline void use_groupserv_set_symbols(module_t *m)
{
    MODULE_TRY_REQUEST_DEPENDENCY(m, "groupserv/set");

    mowgli_patricia_t **gs_set_cmdtree_tmp;
    MODULE_TRY_REQUEST_SYMBOL(m, gs_set_cmdtree_tmp, "groupserv/set", "gs_set_cmdtree");
    gs_set_cmdtree = *gs_set_cmdtree_tmp;
}

#endif

#endif

/***********************************************************************
 *          C_AGENT22.C
 *          Agent22 GClass.
 *
 *          Yuneta Agent22, the first authority of realms and yunos in a host
 *
 *          Copyright (c) 2022 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <grp.h>
#include <errno.h>
#include <regex.h>
#include <unistd.h>
#include "c_agent22.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/
#define SDATA_GET_ID(hs)  kw_get_str((hs), "id", "", KW_REQUIRED)
#define SDATA_GET_STR(hs, field)  kw_get_str((hs), (field), "", KW_REQUIRED)
#define SDATA_GET_INT(hs, field)  kw_get_int((hs), (field), 0, KW_REQUIRED)
#define SDATA_GET_BOOL(hs, field)  kw_get_bool((hs), (field), 0, KW_REQUIRED)
#define SDATA_GET_ITER(hs, field)  kw_get_list((hs), (field), 0, KW_REQUIRED)
#define SDATA_GET_JSON(hs, field)  kw_get_dict_value((hs), (field), 0, KW_REQUIRED)

#define SDATA_SET_STR(hs, key, value) json_object_set_new((hs), (key), json_string(value))
#define SDATA_SET_INT(hs, key, value) json_object_set_new((hs), (key), json_integer(value))
#define SDATA_SET_BOOL(hs, key, value) json_object_set_new((hs), (key), value?json_true():json_false())
#define SDATA_SET_JSON(hs, key, value) json_object_set((hs), (key), value)
#define SDATA_SET_JSON_NEW(hs, key, value) json_object_set_new((hs), (key), value)


/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE int audit_command_cb(const char *command, json_t *kw, void *user_data);

PRIVATE int add_console_in_input_gate(hgobj gobj, const char *name, hgobj src);
PRIVATE int add_console_route(
    hgobj gobj,
    const char *name,
    json_t *jn_console,
    hgobj src,
    json_t *kw
);
PRIVATE int remove_console_route(
    hgobj gobj,
    const char *name,
    const char *route_service,
    const char *route_child
);

/***************************************************************************
 *              Resources
 ***************************************************************************/


/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_list_consoles(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_open_console(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_close_console(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE sdata_desc_t pm_help[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "cmd",          0,              0,          "command about you want help"),
SDATAPM (ASN_UNSIGNED,  "level",        0,              0,          "command search level in childs"),
SDATA_END()
};

PRIVATE sdata_desc_t pm_open_console[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "name",         0,              "",         "Name of console"),
SDATAPM (ASN_OCTET_STR, "process",      0,              "bash",     "Process to execute"),
SDATAPM (ASN_OCTET_STR, "cwd",          0,              0,          "Current work directory"),
SDATAPM (ASN_BOOLEAN,   "hold_open",    0,              0,          "True to not close pty on client disconnection"),
SDATAPM (ASN_UNSIGNED,  "cx",           0,              "80",       "Columns"),
SDATAPM (ASN_UNSIGNED,  "cy",           0,              "24",       "Rows"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_close_console[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "name",         0,              "",         "Name of console"),
SDATAPM (ASN_BOOLEAN,   "force",        0,              0,          "Force to close although hold_open TRUE"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_write_tty[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
    SDATAPM (ASN_OCTET_STR, "name",         0,              0,          "Name of console"),
    SDATAPM (ASN_OCTET_STR, "content64",    0,              0,          "Content64 data to write to tty"),
    SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};
PRIVATE const char *a_write_tty[] = {"EV_WRITE_TTY", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD2--type-----------name----------------flag----------------alias---------------items-----------json_fn---------description---------- */
SDATACM2 (ASN_SCHEMA,   "help",             0,                  a_help,             pm_help,        cmd_help,       "Command's help"),
SDATACM2 (ASN_SCHEMA,   "write-tty",        0,                  a_write_tty,        pm_write_tty,   0,              "Write data to tty"),
// HACK DANGER backdoor, use Yuneta only in private networks, or public but encrypted and assured connections.
SDATACM2 (ASN_SCHEMA,    "list-consoles",   0,                  0,                  0,              cmd_list_consoles, "List consoles"),
SDATACM2 (ASN_SCHEMA,    "open-console",    0,                  0,                  pm_open_console,cmd_open_console, "Open console"),
SDATACM2 (ASN_SCHEMA,    "close-console",   0,                  0,                  pm_close_console,cmd_close_console,"Close console"),

SDATA_END()
};

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag----------------default---------description---------- */
SDATA (ASN_OCTET_STR,   "__username__",     SDF_RD,             "",             "Username"),
SDATA (ASN_OCTET_STR,   "tranger_path",     SDF_RD,             "/yuneta/store/agent2/yuneta_agent2.trdb", "tranger path"),
SDATA (ASN_OCTET_STR,   "startup_command",  SDF_RD,             0,              "Command to execute at startup"),
SDATA (ASN_JSON,        "agent22_environment",SDF_RD,             0,              "Agent22 environment. Override the yuno environment"),
SDATA (ASN_JSON,        "node_variables",   SDF_RD,             0,              "Global to Node json config variables"),
SDATA (ASN_INTEGER,     "timerStBoot",      SDF_RD,             6*1000,         "Timer to run yunos on boot"),
SDATA (ASN_INTEGER,     "signal2kill",      SDF_RD,             SIGQUIT,        "Signal to kill yunos"),

SDATA (ASN_JSON,        "range_ports",      SDF_RD,             "[[11100,11199]]", "Range Ports"),
SDATA (ASN_UNSIGNED,    "last_port",        SDF_WR,             0,              "Last port assigned"),
SDATA (ASN_UNSIGNED,    "max_consoles",     SDF_WR,             10,             "Maximum consoles opened"),

SDATA (ASN_POINTER,     "user_data",        0,                  0,              "User data"),
SDATA (ASN_POINTER,     "user_data2",       0,                  0,              "More user data"),
SDATA (ASN_POINTER,     "subscriber",       0,                  0,              "Subscriber of output-events. Not a child gobj"),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_MESSAGES = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"messages",        "Trace messages"},
{0, 0},
};

/*---------------------------------------------*
 *      GClass authz levels
 *---------------------------------------------*/

PRIVATE sdata_desc_t authz_table[] = {
/*-AUTHZ-- type---------name----------------flag----alias---items---description--*/
SDATAAUTHZ (ASN_SCHEMA, "open-console",     0,      0,      0,      "Permission to open console"),
SDATAAUTHZ (ASN_SCHEMA, "close-console",    0,      0,      0,      "Permission to close console"),
SDATAAUTHZ (ASN_SCHEMA, "list-consoles",    0,      0,      0,      "Permission to list consoles"),
SDATA_END()
};

/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t timerStBoot;
    BOOL enabled_yunos_running;

    hgobj gobj_tranger;
    json_t *tranger;

    json_t *list_consoles; // Dictionary of console names

    hgobj resource;
    hgobj timer;
    hrotatory_t audit_file;
} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*----------------------------------------*
     *  Check node_owner
     *----------------------------------------*/
    const char *node_owner = gobj_node_owner();
    if(empty_string(node_owner)) {
        node_owner = "none";
        gobj_set_node_owner(node_owner);

        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "node_owner EMPTY, setting none",
            NULL
        );
    }

    /*----------------------------------------*
     *  Check AUTHZS
     *----------------------------------------*/
    BOOL is_yuneta = FALSE;
    struct passwd *pw = getpwuid(getuid());
    if(strcmp(pw->pw_name, "yuneta")==0) {
        gobj_write_str_attr(gobj, "__username__", "yuneta");
        is_yuneta = TRUE;
    } else {
        static gid_t groups[30]; // HACK to use outside
        int ngroups = sizeof(groups)/sizeof(groups[0]);

        getgrouplist(pw->pw_name, 0, groups, &ngroups);
        for(int i=0; i<ngroups; i++) {
            struct group *gr = getgrgid(groups[i]);
            if(strcmp(gr->gr_name, "yuneta")==0) {
                gobj_write_str_attr(gobj, "__username__", "yuneta");
                is_yuneta = TRUE;
                break;
            }
        }
    }
    if(!is_yuneta) {
        trace_msg("User or group 'yuneta' is needed to run %s", gobj_yuno_role());
        printf("User or group 'yuneta' is needed to run %s\n", gobj_yuno_role());
        exit(0);
    }

    priv->timer = gobj_create("", GCLASS_TIMER, 0, gobj);

    /*---------------------------------------*
     *      Check if already running
     *---------------------------------------*/
    {
        const char *pidfile = "/yuneta/realms/agent/yuneta_agent22.pid";
        int pid = 0;

        FILE *file = fopen(pidfile, "r");
        if(file) {
            fscanf(file, "%d", &pid);
            fclose(file);

            int ret = kill(pid, 0);
            if(ret == 0) {
                log_info(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_INFO,
                    "msg",          "%s", "yuneta_agent22 already running, exiting",
                    "pid",          "%d", pid,
                    NULL
                );
                exit(0);
            } else if(errno == ESRCH) {
                unlink(pidfile);
            } else {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_SYSTEM_ERROR,
                    "msg",          "%s", "cannot check pid",
                    "pid",          "%d", pid,
                    "errno",        "%d", errno,
                    "serrno",       "%s", strerror(errno),
                    NULL
                );
            }

        }
        file = fopen(pidfile, "w");
        if(file) {
            fprintf(file, "%d\n", getpid());
            fclose(file);
        }
    }

    if(1) {
        /*-----------------------------*
         *      Audit
         *-----------------------------*/
        char audit_path[NAME_MAX];
        yuneta_realm_file(audit_path, sizeof(audit_path), "audit", "ZZZ-DD_MM_CCYY.log", TRUE);
        priv->audit_file = rotatory_open(
            audit_path,
            0,                      // 0 = default 64K
            0,                      // 0 = default 8
            0,                      // 0 = default 10
            yuneta_xpermission(),   // permission for directories and executable files. 0 = default 02775
            0660,                   // permission for regular files. 0 = default 0664
            TRUE
        );
        if(priv->audit_file) {
            gobj_audit_commands(audit_command_cb, gobj);
        }
    }

    priv->list_consoles = json_object();

    /*
     *  SERVICE subscription model
     */
    hgobj subscriber = (hgobj)gobj_read_pointer_attr(gobj, "subscriber");
    if(subscriber) {
        gobj_subscribe_event(gobj, NULL, NULL, subscriber);
    }

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(timerStBoot,             gobj_read_int32_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
//     PRIVATE_DATA *priv = gobj_priv_data(gobj);
//
//     IF_EQ_SET_PRIV(timeout,             gobj_read_int32_attr)
//     END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    JSON_DECREF(priv->list_consoles);

    if(priv->audit_file) {
        rotatory_close(priv->audit_file);
        priv->audit_file = 0;
    }
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_start(priv->timer);
    set_timeout(priv->timer, priv->timerStBoot);
    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    clear_timeout(priv->timer);
    gobj_stop(priv->timer);

    return 0;
}

/***************************************************************************
 *      Framework Method
 ***************************************************************************/
PRIVATE int mt_trace_on(hgobj gobj, const char *level, json_t *kw)
{
    treedb_set_trace(TRUE);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *      Framework Method
 ***************************************************************************/
PRIVATE int mt_trace_off(hgobj gobj, const char *level, json_t *kw)
{
    treedb_set_trace(FALSE);

    KW_DECREF(kw);
    return 0;
}




            /***************************
             *      Commands
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    KW_INCREF(kw);
    json_t *jn_resp = gobj_build_cmds_doc(gobj, kw);

    return msg_iev_build_webix(
        gobj,
        0,
        jn_resp,
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_list_consoles(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*----------------------------------------*
     *  Check AUTHZS
     *----------------------------------------*/
    const char *permission = "list-consoles";
    if(!gobj_user_has_authz(gobj, permission, kw_incref(kw), src)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("No permission to '%s'", permission),
            0,
            0,
            kw  // owned
        );
    }

    /*----------------------------------------*
     *  List consoles
     *----------------------------------------*/
    int result = 0;
    json_t *jn_data = json_object();

    const char *name; json_t *jn_console;
    json_object_foreach(priv->list_consoles, name, jn_console) {
        json_t *jn_dup_console = json_deep_copy(jn_console);
        json_object_set_new(jn_data, name, jn_dup_console);

        json_t *jn_routes = kw_get_dict(jn_dup_console, "routes", 0, KW_REQUIRED);
        json_t *jn_gobjs = kw_get_dict(jn_dup_console, "gobjs", json_object(), KW_CREATE);

        const char *route_name; json_t *jn_route;
        json_object_foreach(jn_routes, route_name, jn_route) {
            const char *route_service = kw_get_str(jn_route, "route_service", "", KW_REQUIRED);
            const char *route_child = kw_get_str(jn_route,  "route_child", "", KW_REQUIRED);
            hgobj gobj_route_service = gobj_find_service(route_service, TRUE);
            if(gobj_route_service) {
                hgobj gobj_input_gate = gobj_child_by_name(gobj_route_service, route_child, 0);
                if(!gobj_input_gate) {
                    log_error(0,
                        "gobj",         "%s", gobj_full_name(gobj),
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                        "msg",          "%s", "no route child found",
                        "service",      "%s", route_service,
                        "child",        "%s", route_child,
                        NULL
                    );
                    json_object_set_new(jn_gobjs, route_name, json_string("ERROR route_child not found"));
                    result = -1;
                    continue;
                }
                json_t *jn_consoles = gobj_kw_get_user_data(gobj_input_gate, "consoles", 0, 0);
                json_object_set_new(jn_gobjs, route_name, json_deep_copy(jn_consoles));
            } else {
                json_object_set_new(jn_gobjs, route_name, json_string("ERROR route_service not found"));
                result = -1;
            }
        }
    }

    /*
     *  Inform
     */
    return msg_iev_build_webix(
        gobj,
        result,
        json_sprintf("==> List consoles of agent22: '%s'", node_uuid()),
        0,
        jn_data, // owned
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_open_console(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*----------------------------------------*
     *  Check AUTHZS
     *----------------------------------------*/
    const char *permission = "open-console";
    if(!gobj_user_has_authz(gobj, permission, kw_incref(kw), src)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("No permission to '%s'", permission),
            0,
            0,
            kw  // owned
        );
    }

    /*----------------------------------------*
     *  Open console
     *----------------------------------------*/
    const char *name = kw_get_str(kw, "name", "", 0);
    const char *process = kw_get_str(kw, "process", "bash", 0);
    const char *cwd = kw_get_str(kw, "cwd", "/home/yuneta", 0);
    BOOL hold_open = kw_get_bool(kw, "hold_open", 0, KW_WILD_NUMBER);
    int cx = kw_get_int(kw, "cx", 80, KW_WILD_NUMBER);
    int cy = kw_get_int(kw, "cy", 24, KW_WILD_NUMBER);

    if(empty_string(name)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("What console name?"),
            0,
            0,
            kw  // owned
        );
    }
    if(empty_string(process)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("What process?"),
            0,
            0,
            kw  // owned
        );
    }

    /*
     *  Get a iter of matched resources
     */
    hgobj gobj_console = 0;

    if(!kw_has_key(priv->list_consoles, name)) {
        /*
         *  New console
         */
        if(kw_size(priv->list_consoles) > gobj_read_uint32_attr(gobj, "max_consoles")) {
            return msg_iev_build_webix(
                gobj,
                -1,
                json_sprintf("Too much opened consoles: %d", kw_size(priv->list_consoles)),
                0,
                0,
                kw  // owned
            );
        }

        /*
         *  Create pseudoterminal
         */
        json_t *kw_pty = json_pack("{s:s, s:s, s:i, s:i}",
            "process", process,
            "cwd", cwd,
            "cols", cx,
            "rows", cy
        );
        gobj_console = gobj_create_unique(name, GCLASS_PTY, kw_pty, gobj);
        if(!gobj_console) {
            return msg_iev_build_webix(
                gobj,
                -1,
                json_sprintf("Cannot open console: '%s'", name),
                0,
                0,
                kw  // owned
            );
        }
        gobj_set_volatil(gobj_console, TRUE);

        /*
         *  Save console
         */
        json_t *jn_console = json_pack("{s:s, s:b, s:{}}",
            "process", process,
            "hold_open", hold_open,
            "routes"
        );

        add_console_route(gobj, name, jn_console, src, kw);

        json_object_set(priv->list_consoles, name, jn_console); // save in local list

        json_decref(jn_console);

        gobj_start(gobj_console);

    } else {
        /*
         *  Console already exists
         */
        json_t *jn_console = kw_get_dict(priv->list_consoles, name, 0, KW_REQUIRED);
        gobj_console = gobj_find_unique_gobj(name, FALSE);
        if(!gobj_console) {
            return msg_iev_build_webix(
                gobj,
                -1,
                json_sprintf("Console gobj not found: '%s'", name),
                0,
                0,
                kw  // owned
            );
        }
        int ret = add_console_route(gobj, name, jn_console, src, kw);
        if(ret < 0) {
            if(ret == -2) {
                return msg_iev_build_webix(
                    gobj,
                    -1,
                    json_sprintf("Console already open: '%s'", name),
                    0,
                    0,
                    kw  // owned
                );
            } else {
                return msg_iev_build_webix(
                    gobj,
                    -1,
                    json_sprintf("Error opening console: '%s'", name),
                    0,
                    0,
                    kw  // owned
                );
            }
        }
    }

    /*
     *  Inform
     */
    return msg_iev_build_webix(
        gobj,
        0,
        0,
        0,
        json_sprintf("Console opened: '%s'", name),  // owned
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_close_console(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*----------------------------------------*
     *  Check AUTHZS
     *----------------------------------------*/
    const char *permission = "close-console";
    if(!gobj_user_has_authz(gobj, permission, kw_incref(kw), src)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("No permission to '%s'", permission),
            0,
            0,
            kw  // owned
        );
    }


    /*----------------------------------------*
     *  Close console
     *----------------------------------------*/
    const char *name = kw_get_str(kw, "name", "", 0);
    BOOL force = kw_get_bool(kw, "force", 0, KW_WILD_NUMBER);

    if(empty_string(name)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("What console name?"),
            0,
            0,
            kw  // owned
        );
    }

    json_t *jn_console = kw_get_dict(priv->list_consoles, name, 0, 0);
    if(!jn_console) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("Console not found: '%s'", name),
            0,
            0,
            kw  // owned
        );
    }

    BOOL hold_open = kw_get_bool(jn_console, "hold_open", 0, KW_REQUIRED);
    if(force) {
        hold_open = FALSE;
    }

    /*
     *  Delete console or route
     */
    int ret = 0;
    if(hold_open) {
        const char *route_service = gobj_name(gobj_nearest_top_unique(src));
        const char *route_child = gobj_name(src);
        ret = remove_console_route(gobj, name, route_service, route_child);
    } else {
        hgobj gobj_console = gobj_find_unique_gobj(name, TRUE);
        gobj_stop(gobj_console); // volatil, auto-destroy
    }

    /*
     *  Inform
     */
    return msg_iev_build_webix(
        gobj,
        ret,
        json_sprintf("Console closed: '%s'", name),
        0,
        0, // owned
        kw  // owned
    );
}




            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int add_console_route(
    hgobj gobj,
    const char *name,
    json_t *jn_console_,
    hgobj src,
    json_t *kw
)
{
    json_t *jn_routes = kw_get_dict(jn_console_, "routes", 0, KW_REQUIRED);

    const char *route_service = gobj_name(gobj_nearest_top_unique(src));
    const char *route_child = gobj_name(src);

    char route_name[NAME_MAX];
    snprintf(route_name, sizeof(route_name), "%s.%s", route_service, route_child);

    if(kw_has_key(jn_routes, route_name)) {
        return -2;
    }

    /*
     *  add in local list
     */
    json_t *jn_route = json_pack("{s:s, s:s, s:O}",
        "route_service", route_service,
        "route_child", route_child,
        "__md_iev__", kw_get_dict(kw, "__md_iev__", 0, KW_REQUIRED)
    );
    if(!jn_route) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "cannot create route",
            "route_service","%s", route_service,
            "route_child",  "%s", route_child,
            "kw",           "%j", kw,
            NULL
        );
        return -1;
    }


    json_object_set_new(jn_routes, route_name, jn_route);

    /*
     *  add in input gate
     */
    return add_console_in_input_gate(gobj, name, src);
}

/***************************************************************************
 *  Delete route in local list and input gate
 ***************************************************************************/
PRIVATE int remove_console_route(
    hgobj gobj,
    const char *name,
    const char *route_service,
    const char *route_child
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *jn_console_ = kw_get_dict(priv->list_consoles, name, 0, 0);
    json_t *jn_routes = kw_get_dict(jn_console_, "routes", 0, KW_REQUIRED);

    char route_name[NAME_MAX];
    snprintf(route_name, sizeof(route_name), "%s.%s", route_service, route_child);

    /*
     *  delete in local list
     */
    if(kw_has_key(jn_routes, route_name)) {
        json_object_del(jn_routes, route_name);
    } else {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "route not exist in local list",
            "name",         "%s", route_name,
            NULL
        );
    }

    /*
     *  delete in input gate
     */
    hgobj gobj_route_service = gobj_find_service(route_service, TRUE);
    if(gobj_route_service) {
        hgobj gobj_input_gate = gobj_child_by_name(gobj_route_service, route_child, 0);
        if(gobj_input_gate) {
            json_t *consoles = gobj_kw_get_user_data(gobj_input_gate, "consoles", 0, 0);
            if(consoles) {
                json_object_del(consoles, route_name);
            } else {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                    "msg",          "%s", "no route found in child gobj",
                    "route_name",   "%s", route_name,
                    "service",      "%s", route_service,
                    "child",        "%s", route_child,
                    NULL
                );
            }
        } else {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "no route child gobj found",
                "service",      "%s", route_service,
                "child",        "%s", route_child,
                NULL
            );
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int add_console_in_input_gate(hgobj gobj, const char *name, hgobj src)
{
    char name_[NAME_MAX];
    snprintf(name_, sizeof(name_), "consoles`%s", name);
    gobj_kw_get_user_data( // save in input gate
        src,
        name_,
        json_true(), // owned
        KW_CREATE
    );

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int delete_console(hgobj gobj, const char *name)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*
     *  delete in local list
     */
    json_t *jn_console = kw_get_dict(priv->list_consoles, name, 0, KW_EXTRACT);

    hgobj gobj_console = gobj_find_unique_gobj(name, FALSE);

    if(!jn_console) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "no console conf found",
            "name",         "%s", name,
            NULL
        );
        if(gobj_console) {
            gobj_stop(gobj_console); // volatil, auto-destroy
        }
        return -1;
    }

    /*
     *  delete routes in input gates
     */
    json_t *jn_routes = kw_get_dict(jn_console, "routes", 0, KW_REQUIRED);

    const char *route; json_t *jn_route; void *n;
    json_object_foreach_safe(jn_routes, n, route, jn_route) {
        const char *route_service = kw_get_str(jn_route, "route_service", "", KW_REQUIRED);
        const char *route_child = kw_get_str(jn_route,  "route_child", "", KW_REQUIRED);
        hgobj gobj_route_service = gobj_find_service(route_service, TRUE);
        if(gobj_route_service) {
            hgobj gobj_input_gate = gobj_child_by_name(gobj_route_service, route_child, 0);
            if(!gobj_input_gate) {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                    "msg",          "%s", "no route child found",
                    "service",      "%s", route_service,
                    "child",        "%s", route_child,
                    NULL
                );
                continue;
            }
            json_t *consoles = gobj_kw_get_user_data(gobj_input_gate, "consoles", 0, 0);
            if(consoles) {
                json_object_del(consoles, name);
            }

        }
    }

    if(gobj_console) {
        gobj_stop(gobj_console); // volatil, auto-destroy
    }
    json_decref(jn_console);

    return 0;
}

/***************************************************************************
 *  From input gate
 ***************************************************************************/
PRIVATE int delete_consoles_on_disconnection(hgobj gobj, json_t *kw, hgobj src_)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    hgobj gobj_channel = (hgobj)(size_t)kw_get_int(kw, "__temp__`channel_gobj", 0, KW_REQUIRED);
    json_t *consoles = gobj_kw_get_user_data(gobj_channel, "consoles", 0, 0);
    if(!consoles) {
        return 0;
    }

    const char *route_service = gobj_name(gobj_nearest_top_unique(gobj_channel));
    const char *route_child = gobj_name(gobj_channel);

    const char *name; json_t *jn_; void *n;
    json_object_foreach_safe(consoles, n, name, jn_) {
        json_t *jn_console = kw_get_dict(priv->list_consoles, name, 0, 0);

        BOOL hold_open = kw_get_bool(jn_console, "hold_open", 0, 0);
        if(hold_open) {
            remove_console_route(gobj, name, route_service, route_child);
        } else {
            delete_console(gobj, name);
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int audit_command_cb(const char *command, json_t *kw, void *user_data)
{
    hgobj gobj = user_data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->audit_file) {
        if(!kw) {
            kw = json_object();
        } else {
            KW_INCREF(kw);
        }
        char fecha[32];
        current_timestamp(fecha, sizeof(fecha));
        json_t *jn_cmd = json_pack("{s:s, s:s, s:o}",
            "command", command,
            "date", fecha,
            "kw", kw
        );
        if(jn_cmd) {
            char *audit = json2str(jn_cmd);
            if(audit) {
                rotatory_write(priv->audit_file, LOG_AUDIT, audit, strlen(audit));
                rotatory_write(priv->audit_file, LOG_AUDIT, "\n", 1);  // double new line: the separator field
                gbmem_free(audit);
            }
            json_decref(jn_cmd);
        }
    }
    return 0;
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_on_open(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_on_close(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    delete_consoles_on_disconnection(gobj, kw, src);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_tty_open(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *jn_console = kw_get_dict(priv->list_consoles, gobj_name(src), 0, KW_REQUIRED);
    if(jn_console) {
        json_t *jn_routes = kw_get_dict(jn_console, "routes", 0, KW_REQUIRED);

        const char *route_name; json_t *jn_route;
        json_object_foreach(jn_routes, route_name, jn_route) {
            const char *route_service = kw_get_str(jn_route, "route_service", "", KW_REQUIRED);
            const char *route_child = kw_get_str(jn_route,  "route_child", "", KW_REQUIRED);
            hgobj gobj_route_service = gobj_find_service(route_service, TRUE);
            if(!gobj_route_service) {
                continue;
            }
            hgobj gobj_input_gate = gobj_child_by_name(gobj_route_service, route_child, 0);
            if(!gobj_input_gate) {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                    "msg",          "%s", "no route child found",
                    "service",      "%s", route_service,
                    "child",        "%s", route_child,
                    NULL
                );
                continue;
            }

            gobj_send_event(
                gobj_input_gate,
                "EV_TTY_OPEN",
                msg_iev_build_webix2(gobj,
                    0,  // result
                    0,  // comment
                    0,  // schema
                    json_incref(kw), // owned
                    json_incref(jn_route),  // owned
                    ""
                ),
                gobj
            );
        }
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_tty_close(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_is_shutdowning()) {
        KW_DECREF(kw);
        return 0;
    }

    json_t *jn_console = kw_get_dict(priv->list_consoles, gobj_name(src), 0, KW_EXTRACT);
    if(jn_console) {
        json_t *jn_routes = kw_get_dict(jn_console, "routes", 0, KW_REQUIRED);

        const char *route_name; json_t *jn_route; void *n;
        json_object_foreach_safe(jn_routes, n, route_name, jn_route) {
            const char *route_service = kw_get_str(jn_route, "route_service", "", KW_REQUIRED);
            const char *route_child = kw_get_str(jn_route,  "route_child", "", KW_REQUIRED);
            hgobj gobj_route_service = gobj_find_service(route_service, TRUE);
            if(!gobj_route_service) {
                continue;
            }
            hgobj gobj_input_gate = gobj_child_by_name(gobj_route_service, route_child, 0);
            if(!gobj_input_gate) {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                    "msg",          "%s", "no route child found",
                    "service",      "%s", route_service,
                    "child",        "%s", route_child,
                    NULL
                );
                continue;
            }

            json_t *consoles = gobj_kw_get_user_data(gobj_input_gate, "consoles", 0, 0);

            if(consoles) {
                json_object_del(consoles, gobj_name(src));
            }

            gobj_send_event(
                gobj_input_gate,
                "EV_TTY_CLOSE",
                msg_iev_build_webix2(gobj,
                    0,  // result
                    0,  // comment
                    0,  // schema
                    json_incref(kw), // owned
                    json_incref(jn_route),  // owned
                    ""
                ),
                gobj
            );
        }

        json_decref(jn_console);
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_tty_data(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *jn_console = kw_get_dict(priv->list_consoles, gobj_name(src), 0, KW_REQUIRED);
    if(jn_console) {
        json_t *jn_routes = kw_get_dict(jn_console, "routes", 0, KW_REQUIRED);

        const char *route_name; json_t *jn_route;
        json_object_foreach(jn_routes, route_name, jn_route) {
            const char *route_service = kw_get_str(jn_route, "route_service", "", KW_REQUIRED);
            const char *route_child = kw_get_str(jn_route,  "route_child", "", KW_REQUIRED);
            hgobj gobj_route_service = gobj_find_service(route_service, TRUE);
            if(!gobj_route_service) {
                continue;
            }
            hgobj gobj_input_gate = gobj_child_by_name(gobj_route_service, route_child, 0);
            if(!gobj_input_gate) {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                    "msg",          "%s", "no route child found",
                    "service",      "%s", route_service,
                    "child",        "%s", route_child,
                    NULL
                );
                continue;
            }

            gobj_send_event(
                gobj_input_gate,
                "EV_TTY_DATA",
                msg_iev_build_webix2(gobj,
                    0,  // result
                    0,  // comment
                    0,  // schema
                    json_incref(kw), // owned
                    json_incref(jn_route),  // owned
                    ""
                ),
                gobj
            );
        }
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_write_tty(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    const char *name= kw_get_str(kw, "name", 0, 0);
    const char *content64 = kw_get_str(kw, "content64", 0, 0);
    if(empty_string(content64)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PROTOCOL_ERROR,
            "msg",          "%s", "content64 required",
            "name",         "%s", name,
            NULL
        );
        gobj_send_event(src, "EV_DROP", 0, gobj);
        KW_DECREF(kw);
        return 0;
    }

    hgobj gobj_console = gobj_find_unique_gobj(name, FALSE);
    if(!gobj_console) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PROTOCOL_ERROR,
            "msg",          "%s", "console not found",
            "name",         "%s", name,
            NULL
        );
        gobj_send_event(src, "EV_DROP", 0, gobj);
        KW_DECREF(kw);
        return 0;
    }

    GBUFFER *gbuf = gbuf_decodebase64string(content64);
    if(!gbuf) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PROTOCOL_ERROR,
            "msg",          "%s", "Bad data",
            "name",         "%s", name,
            NULL
        );
        gobj_send_event(src, "EV_DROP", 0, gobj);
        KW_DECREF(kw);
        return 0;
    }

    json_t *kw_tty = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );
    gobj_send_event(gobj_console, "EV_WRITE_TTY", kw_tty, gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input

    // bottom input
    {"EV_ON_OPEN",          0,  0,  0},
    {"EV_ON_CLOSE",         0,  0,  0},
    {"EV_TTY_DATA",         0,  0,  0},
    {"EV_TTY_OPEN",         0,  0,  0},
    {"EV_TTY_CLOSE",        0,  0,  0},
    {"EV_WRITE_TTY",        0,  0,  0},
    {"EV_TIMEOUT",          0,  0,  0},
    {"EV_FINAL_COUNT",      0,  0,  0},
    {"EV_STOPPED",          0,  0,  0},
    // internal
    {NULL, 0, 0, 0}
};
PRIVATE const EVENT output_events[] = {
    {"EV_PLAY_YUNO_ACK",        EVF_NO_WARN_SUBS,  0,  0},
    {"EV_PAUSE_YUNO_ACK",       EVF_NO_WARN_SUBS,  0,  0},
    {"EV_MT_STATS_ANSWER",      0,  0,  0},
    {"EV_MT_COMMAND_ANSWER",    0,  0,  0},
    {NULL, 0, 0, 0}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_ON_OPEN",              ac_on_open,             0},
    {"EV_ON_CLOSE",             ac_on_close,            0},
    {"EV_TTY_DATA",             ac_tty_data,            0},
    {"EV_TTY_OPEN",             ac_tty_open,            0},
    {"EV_TTY_CLOSE",            ac_tty_close,           0},
    {"EV_WRITE_TTY",            ac_write_tty,           0},
    {"EV_TIMEOUT",              ac_timeout,             0},
    {"EV_STOPPED",              0,                      0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_IDLE,
    NULL
};

PRIVATE FSM fsm = {
    input_events,
    output_events,
    state_names,
    states,
};

/***************************************************************************
 *              GClass
 ***************************************************************************/
/*---------------------------------------------*
 *              Local methods table
 *---------------------------------------------*/
PRIVATE LMETHOD lmt[] = {
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_AGENT22_NAME,
    &fsm,
    {
        mt_create,
        0, //mt_create2,
        mt_destroy,
        mt_start,
        mt_stop,
        0, //
        0, //mt_pause,
        mt_writing,
        0, //mt_reading,
        0, //mt_subscription_added,
        0, //mt_subscription_deleted,
        0, //mt_child_added,
        0, //mt_child_removed,
        0, //mt_stats,
        0, //mt_command,
        0, //mt_inject_event,
        0, //mt_create_resource,
        0, //mt_list_resource,
        0, //mt_save_resource,
        0, //mt_delete_resource,
        0, //mt_future21
        0, //mt_future22
        0, //mt_get_resource
        0, //mt_state_changed,
        0, //mt_authenticate,
        0, //mt_list_childs,
        0, //mt_stats_updated,
        0, //mt_disable,
        0, //mt_enable,
        mt_trace_on,
        mt_trace_off,
        0, //mt_gobj_created,
        0, //mt_future33,
        0, //mt_future34,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_authz_checker,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_future44,
        0, //mt_unlink_nodes,
        0, //mt_topic_jtree,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_shoot_snap,
        0, //mt_activate_snap,
        0, //mt_list_snaps,
        0, //mt_treedbs,
        0, //mt_treedb_topics,
        0, //mt_topic_desc,
        0, //mt_topic_links,
        0, //mt_topic_hooks,
        0, //mt_node_parents,
        0, //mt_node_childs,
        0, //mt_list_instances,
        0, //mt_node_tree,
        0, //mt_topic_size,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    authz_table,  // acl
    s_user_trace_level,
    command_table,  // command_table
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_agent22(void)
{
    return &_gclass;
}

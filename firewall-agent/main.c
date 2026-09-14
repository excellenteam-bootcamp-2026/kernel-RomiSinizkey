#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <curl/curl.h>
#include <cjson/cJSON.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/attr.h>

#include "firewall_protocol.h"

/*
 * Node.js rules endpoint (see src/adapters/inbound/http/controllers/
 * firewallController.ts and GetRulesUseCase.ts in the firewall-RomiSinizkey
 * repo). "?type=ip" makes the server return only:
 *
 *   { "ips": { "blacklist": [ {id,type,mode,value,active}, ... ],
 *               "whitelist": [ ... ] } }
 *
 * Overridable via the FIREWALL_API_URL environment variable so this is
 * never hardcoded to one deployment.
 */
#define DEFAULT_RULES_URL "http://localhost:3000/api/firewall/rules?type=ip"

/* Default polling interval, in seconds, used when FIREWALL_POLL_INTERVAL_SECONDS
 * is unset or invalid. Matches the PDF's own suggested value for this stage.
 */
#define DEFAULT_POLL_INTERVAL_SECONDS 10

/* Set only by handle_shutdown_signal(). sig_atomic_t + volatile is the
 * one type safe to read/write both inside a signal handler and in
 * normal code without extra synchronization.
 */
static volatile sig_atomic_t g_running = 1;

struct http_response {
    char *data;
    size_t size;
};

static const char *rules_url(void)
{
    const char *env = getenv("FIREWALL_API_URL");

    return (env && *env) ? env : DEFAULT_RULES_URL;
}

/*
 * Allocates a libnl socket and connects it to the kernel's Generic
 * Netlink bus. This is the one-time, fatal part of setup: it does not
 * depend on firewall_module.ko being loaded, only on the local netlink
 * transport being available, so a failure here is not expected to be
 * transient.
 *
 * On success, returns 0 with the connected socket in *sock_out. On
 * failure, returns a negative value and leaves *sock_out as NULL.
 */
static int connect_netlink(struct nl_sock **sock_out)
{
    struct nl_sock *sock;

    sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "firewall-agent: failed to allocate netlink socket\n");
        return -1;
    }

    if (genl_connect(sock) != 0) {
        fprintf(stderr, "firewall-agent: failed to connect to Generic Netlink\n");
        nl_socket_free(sock);
        return -1;
    }

    *sock_out = sock;
    return 0;
}

/*
 * Resolves the "firewall" Generic Netlink family's current numeric id
 * on the given (already-connected) socket. The id is assigned
 * dynamically by the kernel each time firewall_module.ko registers the
 * family, and is not guaranteed to stay the same across an
 * unload/reload cycle, so it is looked up fresh every sync cycle rather
 * than cached once at startup.
 *
 * On success, returns the non-negative family id. On failure (module
 * not loaded yet, or unloaded since the previous cycle), logs a clear
 * message and returns the negative libnl error - it never terminates
 * the process, since the module may simply not be loaded yet or may
 * come back on a later cycle.
 */
static int resolve_firewall_family(struct nl_sock *sock)
{
    int family_id = genl_ctrl_resolve(sock, FIREWALL_GENL_FAMILY_NAME);

    if (family_id < 0) {
        fprintf(stderr,
            "firewall-agent: could not resolve Generic Netlink family \"%s\" "
            "(is firewall_module.ko loaded?): %s\n",
            FIREWALL_GENL_FAMILY_NAME, nl_geterror(family_id));
    }

    return family_id;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct http_response *resp = userdata;
    size_t chunk_size = size * nmemb;
    char *new_data = realloc(resp->data, resp->size + chunk_size + 1);

    if (!new_data)
        return 0; /* tells curl the write failed */

    resp->data = new_data;
    memcpy(resp->data + resp->size, ptr, chunk_size);
    resp->size += chunk_size;
    resp->data[resp->size] = '\0';

    return chunk_size;
}

/*
 * Performs the HTTP GET against the Node.js rules endpoint and returns
 * the response body as a NUL-terminated, malloc'd string in *out_body
 * (caller must free it). Only a 200 response is treated as success -
 * any transport failure or non-200 status is reported and returns a
 * negative value with *out_body left NULL, so the caller never mistakes
 * a failed fetch for an empty ruleset.
 */
static int fetch_rules(const char *url, char **out_body)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    struct http_response resp = { .data = NULL, .size = 0 };

    *out_body = NULL;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "firewall-agent: failed to initialize curl\n");
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "firewall-agent: HTTP request to %s failed: %s\n",
            url, curl_easy_strerror(res));
        free(resp.data);
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code != 200) {
        fprintf(stderr, "firewall-agent: Node.js API returned HTTP %ld\n", http_code);
        free(resp.data);
        return -1;
    }

    if (!resp.data) {
        fprintf(stderr, "firewall-agent: Node.js API returned an empty body\n");
        return -1;
    }

    *out_body = resp.data;
    return 0;
}

/*
 * Parses the Node.js response body and extracts the IPv4 addresses of
 * every active blacklist rule under "ips.blacklist" into out_ips,
 * writing the count into *out_count. Only rules with active == true are
 * included; inactive rules are skipped, not an error.
 *
 * The entire response is rejected (returns negative, *out_count
 * untouched) if: the body isn't valid JSON, "ips"/"ips.blacklist" is
 * missing or the wrong type, any rule entry is missing "active" or
 * "value", an active rule's "value" isn't a string that parses as a
 * valid IPv4 address, or more than FIREWALL_MAX_RULES active rules are
 * present. Nothing is truncated - an oversized ruleset is a hard error.
 */
static int parse_rules(const char *body, __be32 *out_ips, unsigned int *out_count)
{
    cJSON *root;
    cJSON *ips_obj;
    cJSON *blacklist;
    cJSON *rule = NULL;
    unsigned int count = 0;
    int result = -1;

    root = cJSON_Parse(body);
    if (!root) {
        fprintf(stderr, "firewall-agent: response is not valid JSON\n");
        return -1;
    }

    ips_obj = cJSON_GetObjectItemCaseSensitive(root, "ips");
    if (!cJSON_IsObject(ips_obj)) {
        fprintf(stderr, "firewall-agent: response is missing the \"ips\" object\n");
        goto out;
    }

    blacklist = cJSON_GetObjectItemCaseSensitive(ips_obj, "blacklist");
    if (!cJSON_IsArray(blacklist)) {
        fprintf(stderr, "firewall-agent: response is missing the \"ips.blacklist\" array\n");
        goto out;
    }

    cJSON_ArrayForEach(rule, blacklist) {
        cJSON *active_item;
        cJSON *value_item;
        struct in_addr addr;

        if (!cJSON_IsObject(rule)) {
            fprintf(stderr, "firewall-agent: malformed rule entry in \"ips.blacklist\"\n");
            goto out;
        }

        active_item = cJSON_GetObjectItemCaseSensitive(rule, "active");
        if (!cJSON_IsBool(active_item)) {
            fprintf(stderr, "firewall-agent: rule is missing a valid \"active\" field\n");
            goto out;
        }

        if (!cJSON_IsTrue(active_item))
            continue; /* inactive rule: excluded from the snapshot, not an error */

        value_item = cJSON_GetObjectItemCaseSensitive(rule, "value");
        if (!cJSON_IsString(value_item) || !value_item->valuestring) {
            fprintf(stderr, "firewall-agent: active rule is missing a valid \"value\" field\n");
            goto out;
        }

        if (inet_pton(AF_INET, value_item->valuestring, &addr) != 1) {
            fprintf(stderr, "firewall-agent: \"%s\" is not a valid IPv4 address\n",
                value_item->valuestring);
            goto out;
        }

        if (count >= FIREWALL_MAX_RULES) {
            fprintf(stderr,
                "firewall-agent: API returned more than FIREWALL_MAX_RULES (%d) "
                "active IP blacklist rules\n", FIREWALL_MAX_RULES);
            goto out;
        }

        /* addr.s_addr is already network byte order (see send_ruleset). */
        out_ips[count] = addr.s_addr;
        count++;
    }

    *out_count = count;
    result = 0;

out:
    cJSON_Delete(root);
    return result;
}

/*
 * Builds and sends one FIREWALL_CMD_REPLACE_RULES message containing
 * the complete current snapshot (ips/count), then waits for the
 * kernel's ACK or error reply. count == 0 sends a present-but-empty
 * FIREWALL_A_RULE_LIST, which the kernel treats as "clear the active
 * ruleset" rather than "message missing" - the two are distinguishable
 * on the wire.
 *
 * Byte order: each entry of ips[] is already in network byte order (the
 * same __be32 representation the kernel uses for ip_header->saddr/daddr
 * - see firewall_hook_fn in firewall_module.c), produced by inet_pton()
 * in parse_rules(). Generic Netlink attributes are plain byte
 * containers: nla_put_u32() and the kernel's nla_get_u32() perform no
 * byte-order conversion of their own. So each value is passed into
 * FIREWALL_RULE_A_VALUE unchanged, with no extra htonl()/ntohl() call -
 * adding one would re-swap already-correct bytes and silently send the
 * wrong address on this little-endian VM.
 */
static int send_ruleset(struct nl_sock *sock, int family_id, const __be32 *ips, unsigned int count)
{
    struct nl_msg *msg;
    struct nlattr *rule_list;
    unsigned int i;
    int err;

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "firewall-agent: failed to allocate netlink message\n");
        return -1;
    }

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0,
              NLM_F_REQUEST | NLM_F_ACK, FIREWALL_CMD_REPLACE_RULES,
              FIREWALL_GENL_VERSION)) {
        fprintf(stderr, "firewall-agent: failed to build message header\n");
        nlmsg_free(msg);
        return -1;
    }

    rule_list = nla_nest_start(msg, FIREWALL_A_RULE_LIST);
    if (!rule_list) {
        fprintf(stderr, "firewall-agent: failed to start rule list attribute\n");
        nlmsg_free(msg);
        return -1;
    }

    for (i = 0; i < count; i++) {
        /* The type tag passed here (i + 1) is only a per-entry index
         * inside the nested list; the kernel walks this list with
         * nla_for_each_nested(), which does not inspect it.
         */
        struct nlattr *rule = nla_nest_start(msg, (int)(i + 1));

        if (!rule) {
            fprintf(stderr, "firewall-agent: failed to start rule entry %u\n", i);
            nlmsg_free(msg);
            return -1;
        }

        err = nla_put_u8(msg, FIREWALL_RULE_A_TYPE, FIREWALL_RULE_TYPE_IP);
        err = err ? err : nla_put_u8(msg, FIREWALL_RULE_A_MODE, FIREWALL_RULE_MODE_BLACKLIST);
        err = err ? err : nla_put_u32(msg, FIREWALL_RULE_A_VALUE, ips[i]);
        if (err) {
            fprintf(stderr, "firewall-agent: failed to add rule attributes: %s\n", nl_geterror(err));
            nlmsg_free(msg);
            return err;
        }

        nla_nest_end(msg, rule);
    }

    nla_nest_end(msg, rule_list);

    printf("firewall-agent: sending REPLACE_RULES (%u active IP blacklist rule(s))\n", count);

    err = nl_send_sync(sock, msg); /* sends msg and waits for ACK/error; frees msg either way */
    if (err < 0) {
        fprintf(stderr, "firewall-agent: kernel rejected REPLACE_RULES: %s\n", nl_geterror(err));
        return err;
    }

    printf("firewall-agent: kernel acknowledged REPLACE_RULES\n");
    return 0;
}

/* Records that a shutdown was requested. Async-signal-safe: it only
 * writes a sig_atomic_t, nothing else is safe to do here (no printf,
 * no malloc/free, no libcurl/libnl calls).
 */
static void handle_shutdown_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/*
 * Installs the same handler for SIGINT (Ctrl+C) and SIGTERM (what
 * systemd/kill send by default) so both request a clean shutdown the
 * same way. SA_RESTART is deliberately not set: it makes a blocking
 * sleep() return early (EINTR) as soon as a signal arrives instead of
 * silently continuing to sleep out the rest of the interval, so the
 * main loop notices g_running promptly.
 */
static void install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_shutdown_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/*
 * Reads FIREWALL_POLL_INTERVAL_SECONDS, falling back to
 * DEFAULT_POLL_INTERVAL_SECONDS if it is unset, not a valid number, or
 * not positive - a bad env var should never crash the agent or produce
 * a zero/negative sleep.
 */
static unsigned int poll_interval_seconds(void)
{
    const char *env = getenv("FIREWALL_POLL_INTERVAL_SECONDS");
    char *endptr;
    long value;

    if (!env || !*env)
        return DEFAULT_POLL_INTERVAL_SECONDS;

    value = strtol(env, &endptr, 10);
    if (*endptr != '\0' || value <= 0) {
        fprintf(stderr,
            "firewall-agent: invalid FIREWALL_POLL_INTERVAL_SECONDS \"%s\", using default (%d)\n",
            env, DEFAULT_POLL_INTERVAL_SECONDS);
        return DEFAULT_POLL_INTERVAL_SECONDS;
    }

    return (unsigned int)value;
}

/*
 * Performs one resolve -> fetch -> parse -> send cycle. Never
 * terminates the agent on failure - resolve_firewall_family(),
 * fetch_rules(), parse_rules(), and send_ruleset() each log their own
 * error, and this function just returns a negative value so the caller
 * retries on the next cycle.
 *
 * The family id is re-resolved at the start of every cycle (instead of
 * being cached once at startup) so the agent recovers automatically if
 * the kernel module was not loaded yet, was unloaded, or was reloaded
 * with a different family id. A resolve, fetch, or parse failure
 * returns before send_ruleset() is ever reached, so a bad or
 * unreachable response can never replace the kernel's active ruleset.
 */
static int sync_once(struct nl_sock *sock)
{
    __be32 ips[FIREWALL_MAX_RULES];
    unsigned int count = 0;
    char *body = NULL;
    int family_id;
    int err;

    family_id = resolve_firewall_family(sock);
    if (family_id < 0)
        return family_id;

    err = fetch_rules(rules_url(), &body);
    if (err != 0)
        return err;

    err = parse_rules(body, ips, &count);
    free(body);
    if (err != 0)
        return err;

    return send_ruleset(sock, family_id, ips, count);
}

int main(void)
{
    struct nl_sock *sock = NULL;
    unsigned int interval;

    printf("firewall-agent started\n");

    install_signal_handlers();
    interval = poll_interval_seconds();

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (connect_netlink(&sock) != 0) {
        curl_global_cleanup();
        return 1;
    }

    printf("firewall-agent: polling every %u second(s)\n", interval);

    while (g_running) {
        if (sync_once(sock) != 0)
            fprintf(stderr, "firewall-agent: synchronization cycle failed, will retry\n");
        else
            printf("firewall-agent: synchronization cycle complete\n");

        if (!g_running)
            break;

        sleep(interval);
    }

    nl_socket_free(sock);
    curl_global_cleanup();

    printf("firewall-agent: shutting down\n");
    return 0;
}

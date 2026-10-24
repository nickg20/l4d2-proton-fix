#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Change successfully retrieved InvalidSignature verdicts for L4D2's server
 * and engine DLLs to ValidSignature. Other results and API failures pass through. */
struct pending_signature {
    void *target;
    uint64_t call;
};
static struct pending_signature pending[32];
static unsigned pending_next;
static pthread_mutex_t pending_lock = PTHREAD_MUTEX_INITIALIZER;

static bool signature_path(const char *path)
{
    static const char *const endings[] = {"/left4dead2/bin/server.dll", "/bin/engine.dll"};
    if (!path)
        return false;
    size_t length = strlen(path);
    for (unsigned i = 0; i < sizeof(endings) / sizeof(endings[0]); i++) {
        size_t suffix = strlen(endings[i]);
        if (length >= suffix && !strcmp(path + length - suffix, endings[i]))
            return true;
    }
    return false;
}

static void remember_signature_request(void *target, uint64_t call, const char *filename)
{
    char *path = filename ? realpath(filename, NULL) : NULL;
    bool matched = call && signature_path(path);
    free(path);
    pthread_mutex_lock(&pending_lock);
    /* Drop a stale mapping if Steam reuses a handle, including for a request
     * that is outside our scope. Never reuse an old decision for a new call. */
    for (unsigned i = 0; i < 32; i++) {
        if (pending[i].target == target && pending[i].call == call) {
            pending[i] = (struct pending_signature){0};
        }
    }
    if (matched) {
        struct pending_signature *slot = &pending[pending_next++ % 32];
        *slot = (struct pending_signature){target, call};
    }
    pthread_mutex_unlock(&pending_lock);
}

static void finish_signature_request(void *target, uint64_t call, void *data, int size,
                                     int callback, bool retrieved, bool *failed)
{
    bool matched = false;
    int32_t status;
    if (!retrieved || callback != 705 || size != 4)
        return;
    pthread_mutex_lock(&pending_lock);
    for (unsigned i = 0; i < 32; i++) {
        if (pending[i].target == target && pending[i].call == call) {
            matched = true;
            pending[i] = (struct pending_signature){0};
            break;
        }
    }
    pthread_mutex_unlock(&pending_lock);
    if (matched && data && failed && !*failed) {
        memcpy(&status, data, 4);
        if (status == 0) {
            status = 1;
            memcpy(data, &status, 4);
        }
    }
}

/* ABI-preserving forwarding stubs for native Steam vtables. */
#include "steam_signature_forward.h"

typedef void *(*lookup_fn)(void *, const char *);
typedef void *(*factory_fn)(const char *, int *);
static lookup_fn native_lookup;
static factory_fn native_factory;

enum kind { CLIENT, UTILS };
struct proxy {
    void **vtable;
    void *target;
    enum kind kind;
    struct proxy *next;
    void *methods[64];
};
static pthread_mutex_t proxy_lock = PTHREAD_MUTEX_INITIALIZER;
static struct proxy *proxies;
static bool app_550(void)
{
    const char *app = getenv("SteamAppId");
    const char *game = getenv("SteamGameId");
    return (app && !strcmp(app, "550")) || (game && !strcmp(game, "550"));
}

static void *wrap(void *, enum kind);

static void *client_utils(struct proxy *self, int pipe, const char *version)
{
    void **table = *(void ***)self->target;
    void *(*original)(void *, int, const char *) = (void *)table[9];
    void *result = original(self->target, pipe, version);
    int saved_errno = errno;
    if (version && !strcmp(version, "SteamUtils010"))
        result = wrap(result, UTILS);
    errno = saved_errno;
    return result;
}

static void *client_generic(struct proxy *self, int user, int pipe, const char *version)
{
    void **table = *(void ***)self->target;
    void *(*original)(void *, int, int, const char *) = (void *)table[12];
    void *result = original(self->target, user, pipe, version);
    int saved_errno = errno;
    if (version && !strcmp(version, "SteamUtils010"))
        result = wrap(result, UTILS);
    errno = saved_errno;
    return result;
}

static uint64_t utils_check(struct proxy *self, const char *filename)
{
    void **table = *(void ***)self->target;
    uint64_t (*original)(void *, const char *) = (void *)table[19];
    uint64_t result = original(self->target, filename);
    int saved_errno = errno;
    remember_signature_request(self->target, result, filename);
    errno = saved_errno;
    return result;
}

static bool utils_result(struct proxy *self, uint64_t call, void *data, int size, int callback,
                         bool *failed)
{
    void **table = *(void ***)self->target;
    bool (*original)(void *, uint64_t, void *, int, int, bool *) = (void *)table[13];
    bool result = original(self->target, call, data, size, callback, failed);
    int saved_errno = errno;
    finish_signature_request(self->target, call, data, size, callback, result, failed);
    errno = saved_errno;
    return result;
}

static void *wrap(void *target, enum kind kind)
{
    struct proxy *p;
    if (!target)
        return NULL;
    pthread_mutex_lock(&proxy_lock);
    for (p = proxies; p; p = p->next) {
        if (p->target == target && p->kind == kind) {
            pthread_mutex_unlock(&proxy_lock);
            return p;
        }
    }
    if (!(p = calloc(1, sizeof(*p)))) {
        pthread_mutex_unlock(&proxy_lock);
        return target;
    }
    p->vtable = p->methods;
    p->target = target;
    p->kind = kind;
    memcpy(p->methods, forward_methods, sizeof(p->methods));
    if (kind == CLIENT) {
        p->methods[9] = client_utils;
        p->methods[12] = client_generic;
    } else {
        p->methods[19] = utils_check;
        p->methods[13] = utils_result;
    }
    p->next = proxies;
    proxies = p;
    pthread_mutex_unlock(&proxy_lock);
    return p;
}

static void *create_interface(const char *version, int *return_code)
{
    factory_fn factory = __atomic_load_n(&native_factory, __ATOMIC_ACQUIRE);
    void *result = factory(version, return_code);
    int saved_errno = errno;
    if (app_550() && version &&
        (!strcmp(version, "SteamClient017") || !strcmp(version, "SteamClient020"))) {
        result = wrap(result, CLIENT);
    }
    errno = saved_errno;
    return result;
}

void *dlsym(void *handle, const char *name)
{
    lookup_fn lookup = __atomic_load_n(&native_lookup, __ATOMIC_ACQUIRE);
    void *result;
    Dl_info provider;
    int saved_errno;
    if (!lookup) {
        lookup = (lookup_fn)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.0");
        if (!lookup)
            _exit(125);
        __atomic_store_n(&native_lookup, lookup, __ATOMIC_RELEASE);
    }
    result = lookup(handle, name);
    saved_errno = errno;
    if (result && !strcmp(name, "CreateInterface") && app_550() && dladdr(result, &provider)) {
        const char *base = strrchr(provider.dli_fname, '/');
        base = base ? base + 1 : provider.dli_fname;
        if (!strcmp(base, "steamclient.so")) {
            __atomic_store_n(&native_factory, (factory_fn)result, __ATOMIC_RELEASE);
            result = create_interface;
        }
    }
    errno = saved_errno;
    return result;
}

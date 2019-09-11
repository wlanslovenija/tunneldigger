

from cffi import FFI

ffibuilder = FFI()
ffibuilder.set_source(
    '_conntrack',
    '''
    #include <sys/types.h>

    #include <libnfnetlink/libnfnetlink.h>
    #include <libnetfilter_conntrack/libnetfilter_conntrack.h>
    ''',
    libraries=[
        'nfnetlink',
        'netfilter_conntrack',
    ],
)

ffibuilder.cdef('''
typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;

enum {
    CONNTRACK,
    ...
};

enum nf_conntrack_msg_type {
    NFCT_T_UNKNOWN,
    NFCT_T_NEW,
    NFCT_T_UPDATE,
    NFCT_T_DESTROY,
    NFCT_T_ALL,
    NFCT_T_ERROR,
    ...
};

enum {
    NFCT_CB_FAILURE,
    NFCT_CB_STOP,
    NFCT_CB_CONTINUE,
    NFCT_CB_STOLEN,
    ...
};

enum nf_conntrack_query {
    NFCT_Q_CREATE,
    NFCT_Q_UPDATE,
    NFCT_Q_DESTROY,
    NFCT_Q_GET,
    NFCT_Q_FLUSH,
    NFCT_Q_DUMP,
    NFCT_Q_DUMP_RESET,
    NFCT_Q_CREATE_UPDATE,
    ...
};

enum nf_conntrack_attr {
    ATTR_L3PROTO,
    ATTR_L4PROTO,
    ATTR_IPV4_SRC,
    ATTR_IPV4_DST,
    ATTR_IPV6_SRC,
    ATTR_IPV6_DST,
    ATTR_PORT_SRC,
    ATTR_PORT_DST,
    ...
};

enum {
    NFCT_CMP_ALL,
    NFCT_CMP_MASK,
    ...
};

typedef int nfct_callback(enum nf_conntrack_msg_type type,
                          struct nf_conntrack *ct,
                          void *data);

struct nf_conntrack* nfct_new();
void nfct_destroy(struct nf_conntrack *ct);
struct nfct_handle* nfct_open(u_int8_t subsys_id, unsigned int subscriptions);
int nfct_close(struct nfct_handle * cth);
int nfct_fd(struct nfct_handle *cth);
int nfct_catch(struct nfct_handle *h);
int nfct_callback_register(struct nfct_handle *h,
                           enum nf_conntrack_msg_type type,
                           nfct_callback *cb,
                           void *data);
int nfct_query(struct nfct_handle *h,
               const enum nf_conntrack_query qt,
               const void *data);

int nfct_cmp(const struct nf_conntrack *ct1,
             const struct nf_conntrack *ct2,
             unsigned int flags);

void nfct_set_attr_u8(struct nf_conntrack *ct,
                      const enum nf_conntrack_attr type,
                      uint8_t value);

void nfct_set_attr_u16(struct nf_conntrack *ct,
                       const enum nf_conntrack_attr type,
                       uint16_t value);

void nfct_set_attr_u32(struct nf_conntrack *ct,
                       const enum nf_conntrack_attr type,
                       uint32_t value);

void nfct_set_attr_u64(struct nf_conntrack *ct,
                       const enum nf_conntrack_attr type,
                       uint64_t value);

extern "Python" int query_callback(enum nf_conntrack_msg_type type,
                                   struct nf_conntrack *ct,
                                   void *data);
''')

if __name__ == '__main__':
    ffibuilder.compile(verbose=True)

#define SECP256K1_CONTEXT_VERIFY ...
#define SECP256K1_CONTEXT_SIGN ...
#define SECP256K1_EC_COMPRESSED ...
#define SECP256K1_EC_UNCOMPRESSED ...

typedef struct secp256k1_context_struct secp256k1_context;

secp256k1_context* secp256k1_context_create(
    unsigned int flags
);
int secp256k1_context_randomize(
    secp256k1_context* ctx,
    const unsigned char *seed32
);
void secp256k1_context_destroy(
    secp256k1_context* ctx
);

typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

int secp256k1_ec_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const unsigned char *input,
    size_t inputlen
);
int secp256k1_ec_pubkey_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_pubkey* pubkey,
    unsigned int flags
);
int secp256k1_ec_pubkey_tweak_add(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak
);
int secp256k1_ec_pubkey_tweak_mul(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak
);
int secp256k1_ec_pubkey_combine(
    const secp256k1_context* ctx,
    secp256k1_pubkey *out,
    const secp256k1_pubkey * const * ins,
    size_t n
);
typedef struct {
    unsigned char data[64];
} secp256k1_ecdsa_signature;

int secp256k1_ecdsa_signature_parse_der(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char *input,
    size_t inputlen
);
int secp256k1_ecdsa_signature_serialize_der(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_ecdsa_signature* sig
);
int secp256k1_ecdsa_verify(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey
);

typedef int (*secp256k1_nonce_function)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
);

int secp256k1_ecdsa_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

int secp256k1_tagged_sha256(
    const secp256k1_context* ctx,
    unsigned char *hash32,
    const unsigned char *tag,
    size_t taglen,
    const unsigned char *msg,
    size_t msglen
);

typedef struct {
    unsigned char data[64];
} secp256k1_xonly_pubkey;

int secp256k1_xonly_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_xonly_pubkey* pubkey,
    const unsigned char *input32
);

int secp256k1_xonly_pubkey_serialize(
    const secp256k1_context* ctx,
    unsigned char *output32,
    const secp256k1_xonly_pubkey* pubkey
);

int secp256k1_xonly_pubkey_from_pubkey(
    const secp256k1_context* ctx,
    secp256k1_xonly_pubkey *xonly_pubkey,
    int *pk_parity,
    const secp256k1_pubkey *pubkey
);

typedef struct {
    unsigned char data[96];
} secp256k1_keypair;

int secp256k1_keypair_create(
    const secp256k1_context* ctx,
    secp256k1_keypair *keypair,
    const unsigned char *seckey
);

int secp256k1_schnorrsig_sign32(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    /* Not really void: secp256k1_keypair */
    const void *keypair,
    const unsigned char *aux_rand32
);

int secp256k1_schnorrsig_verify(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg,
    size_t msglen,
    /* Not really void: secp256k1_xonly_pubkey */
    const void *xonly_pubkey
);

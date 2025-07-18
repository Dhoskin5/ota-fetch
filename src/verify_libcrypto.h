#ifndef VERIFY_LIBCRYPTO_H
#define VERIFY_LIBCRYPTO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VERIFY_ERRBUF_LEN 256

typedef enum {
	VERIFY_OK = 0,
	VERIFY_ERR_OPEN_FILE,
	VERIFY_ERR_LOAD_CERT,
	VERIFY_ERR_LOAD_CA,
	VERIFY_ERR_CERT_VERIFY,
	VERIFY_ERR_LOAD_PUBKEY,
	VERIFY_ERR_READ_SIG,
	VERIFY_ERR_MEM,
	VERIFY_ERR_SIG_VERIFY,
	VERIFY_ERR_HASH,
	VERIFY_ERR_UNKNOWN
} verify_result_t;

/**
 * @brief Verifies a detached signature using a signer certificate and trusted
 * CA(s).
 *
 * @param data_path   Path to the original data file (e.g. manifest.json)
 * @param sig_path    Path to the detached signature file (e.g.
 * manifest.json.sig)
 * @param cert_path   Path to the PEM signing certificate (e.g. manifest.crt)
 * @param ca_path     Path to the trusted root CA bundle (PEM, e.g. rootCA.pem
 * or system bundle)
 * @param errbuf      Buffer for a human-readable error string (can be NULL)
 * @param errbuf_len  Length of errbuf
 * @return VERIFY_OK (0) if signature is valid and cert chains to CA, otherwise
 * error code
 */
verify_result_t verify_signature_with_cert(const char *data_path,
					   const char *sig_path,
					   const char *cert_path,
					   const char *ca_path, char *errbuf,
					   size_t errbuf_len);

#ifdef __cplusplus
}
#endif

#endif // VERIFY_LIBCRYPTO_H

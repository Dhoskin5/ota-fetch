#include "verify_libcrypto.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "logging.h"

/* ------------------------------------------------------------------------ */
static const char *friendly_key_type_name(EVP_PKEY *pkey, char *tmp,
					  size_t tmp_len) {
	const EC_KEY *ec_key = NULL;
	const EC_GROUP *ec_group = NULL;
	const char *curve_name = NULL;
	int key_type;
	int curve_nid;
	int written;

	if (!pkey)
		return "unknown";

	key_type = EVP_PKEY_base_id(pkey);
	switch (key_type) {
	case EVP_PKEY_ED25519:
		return "Ed25519";
	case EVP_PKEY_EC:
		ec_key = EVP_PKEY_get0_EC_KEY(pkey);
		if (!ec_key)
			return "ECDSA";
		ec_group = EC_KEY_get0_group(ec_key);
		if (!ec_group)
			return "ECDSA";
		curve_nid = EC_GROUP_get_curve_name(ec_group);
		if (curve_nid == NID_undef)
			return "ECDSA";
		if (curve_nid == NID_X9_62_prime256v1)
			curve_name = "P-256";
		else
			curve_name = OBJ_nid2sn(curve_nid);
		if (!curve_name || !tmp || tmp_len == 0)
			return "ECDSA";
		written = snprintf(tmp, tmp_len, "ECDSA %s", curve_name);
		if (written < 0 || (size_t)written >= tmp_len)
			return "ECDSA";
		return tmp;
	case EVP_PKEY_RSA:
		return "RSA";
	default:
		return "unknown";
	}
}

/* ------------------------------------------------------------------------ */
static void format_openssl_errors(char *errbuf, size_t len) {
	unsigned long err;
	size_t used = 0;

	if (!errbuf || len == 0)
		return;

	errbuf[0] = '\0';
	while ((err = ERR_get_error()) != 0) {
		char msg[256];
		int written;

		ERR_error_string_n(err, msg, sizeof(msg));
		written = snprintf(errbuf + used, len - used, "%s%s",
				   used ? "; " : "", msg);
		if (written < 0 || (size_t)written >= len - used) {
			errbuf[len - 1] = '\0';
			break;
		}
		used += (size_t)written;
	}
}

/* ------------------------------------------------------------------------ */
static int read_file_all(const char *path, unsigned char **out,
			 size_t *out_len) {
	FILE *fp = NULL;
	unsigned char *buf = NULL;
	long len = 0;
	size_t read_len;

	if (!out || !out_len)
		return 0;

	*out = NULL;
	*out_len = 0;

	fp = fopen(path, "rb");
	if (!fp)
		return 0;

	if (fseek(fp, 0, SEEK_END) != 0)
		goto cleanup;
	len = ftell(fp);
	if (len < 0)
		goto cleanup;
	if (fseek(fp, 0, SEEK_SET) != 0)
		goto cleanup;

	if (len == 0) {
		fclose(fp);
		fp = NULL;
		return 1;
	}

	buf = (unsigned char *)malloc((size_t)len);
	if (!buf)
		goto memfail;

	read_len = fread(buf, 1, (size_t)len, fp);
	if (read_len != (size_t)len)
		goto cleanup;

	fclose(fp);
	fp = NULL;

	*out = buf;
	*out_len = (size_t)len;
	return 1;

memfail:
	fclose(fp);
	fp = NULL;
	return -2;

cleanup:
	if (fp)
		fclose(fp);
	if (buf) {
		OPENSSL_cleanse(buf, (size_t)len);
		free(buf);
	}
	return -1;
}

/* ------------------------------------------------------------------------ */
verify_result_t verify_signature_with_cert(const char *data_path,
					   const char *sig_path,
					   const char *cert_path,
					   const char *ca_path, char *errbuf,
					   size_t errbuf_len) {
	FILE *fp = NULL;
	X509 *signer_cert = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX *ctx = NULL;
	EVP_PKEY *pubkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	BIO *data_bio = NULL;
	unsigned char *sigbuf = NULL;
	unsigned char *data_buf = NULL;
	long siglen = 0;
	size_t data_len = 0;
	int key_type = NID_undef;
	const char *key_name = "unknown";
	const char *openssl_key_name = "unknown";
	char key_name_buf[64];
	verify_result_t result = VERIFY_ERR_UNKNOWN;
	int read_rc;
	struct stat st;

	ERR_clear_error();
	if (errbuf && errbuf_len)
		errbuf[0] = '\0';

	// --- Load signer certificate ---
	fp = fopen(cert_path, "rb");
	if (!fp) {
		result = VERIFY_ERR_OPEN_FILE;
		goto cleanup;
	}
	signer_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	fp = NULL;
	if (!signer_cert) {
		result = VERIFY_ERR_LOAD_CERT;
		goto cleanup;
	}

	// --- Validate signer certificate against CA bundle ---
	store = X509_STORE_new();
	if (!store) {
		result = VERIFY_ERR_MEM;
		goto cleanup;
	}
	if (stat(ca_path, &st) != 0) {
		result = VERIFY_ERR_LOAD_CA;
		goto cleanup;
	}
	if (S_ISDIR(st.st_mode)) {
		if (X509_STORE_load_locations(store, NULL, ca_path) != 1) {
			result = VERIFY_ERR_LOAD_CA;
			goto cleanup;
		}
	} else if (X509_STORE_load_locations(store, ca_path, NULL) != 1) {
		result = VERIFY_ERR_LOAD_CA;
		goto cleanup;
	}
	ctx = X509_STORE_CTX_new();
	if (!ctx) {
		result = VERIFY_ERR_MEM;
		goto cleanup;
	}
	if (X509_STORE_CTX_init(ctx, store, signer_cert, NULL) != 1) {
		result = VERIFY_ERR_CERT_VERIFY;
		goto cleanup;
	}
	if (X509_verify_cert(ctx) != 1) {
		result = VERIFY_ERR_CERT_VERIFY;
		if (errbuf)
			snprintf(errbuf, errbuf_len,
				 "Certificate verification failed: %s",
				 X509_verify_cert_error_string(
				     X509_STORE_CTX_get_error(ctx)));
		goto cleanup;
	}

	// --- Extract public key from signer certificate ---
	pubkey = X509_get_pubkey(signer_cert);
	if (!pubkey) {
		result = VERIFY_ERR_LOAD_PUBKEY;
		goto cleanup;
	}
	key_type = EVP_PKEY_base_id(pubkey);
	key_name = friendly_key_type_name(pubkey, key_name_buf,
					  sizeof(key_name_buf));
	openssl_key_name = OBJ_nid2sn(key_type);
	if (!openssl_key_name)
		openssl_key_name = "unknown";
	LOG_INFO("Signer key type: %s", key_name);
	LOG_DEBUG("Signer key type (OpenSSL): %s", openssl_key_name);

	// --- Read signature file into buffer (detached signature) ---
	fp = fopen(sig_path, "rb");
	if (!fp) {
		result = VERIFY_ERR_OPEN_FILE;
		goto cleanup;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		result = VERIFY_ERR_READ_SIG;
		goto cleanup;
	}
	siglen = ftell(fp);
	if (siglen <= 0) {
		result = VERIFY_ERR_READ_SIG;
		goto cleanup;
	}
	rewind(fp);

	sigbuf = (unsigned char *)malloc(siglen);
	if (!sigbuf) {
		result = VERIFY_ERR_MEM;
		goto cleanup;
	}
	if (fread(sigbuf, 1, siglen, fp) != (size_t)siglen) {
		result = VERIFY_ERR_READ_SIG;
		goto cleanup;
	}
	fclose(fp);
	fp = NULL;

	if (key_type == EVP_PKEY_ED25519) {
		if (siglen != 64) {
			result = VERIFY_ERR_SIG_VERIFY;
			if (errbuf)
				snprintf(errbuf, errbuf_len,
					 "Invalid Ed25519 signature length "
					 "(key type %s, sig len %ld)",
					 key_name, siglen);
			goto cleanup;
		}

		read_rc = read_file_all(data_path, &data_buf, &data_len);
		if (read_rc != 1) {
			result = (read_rc == -2)
				     ? VERIFY_ERR_MEM
				     : (read_rc == 0) ? VERIFY_ERR_OPEN_FILE
						      : VERIFY_ERR_HASH;
			goto cleanup;
		}

		mdctx = EVP_MD_CTX_new();
		if (!mdctx) {
			result = VERIFY_ERR_MEM;
			goto cleanup;
		}
		if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pubkey) !=
		    1) {
			result = VERIFY_ERR_SIG_VERIFY;
			goto cleanup;
		}

		if (EVP_DigestVerify(mdctx, sigbuf, siglen, data_buf,
				     data_len) == 1) {
			result = VERIFY_OK;
		} else {
			result = VERIFY_ERR_SIG_VERIFY;
			if (errbuf)
				snprintf(errbuf, errbuf_len,
					 "Signature verification failed "
					 "(key type %s, sig len %ld)",
					 key_name, siglen);
		}
		goto cleanup;
	}

	if (key_type != EVP_PKEY_EC && key_type != EVP_PKEY_RSA) {
		result = VERIFY_ERR_SIG_VERIFY;
		if (errbuf)
			snprintf(errbuf, errbuf_len,
				 "Unsupported key type %s "
				 "(sig len %ld)",
				 key_name, siglen);
		goto cleanup;
	}

	data_bio = BIO_new_file(data_path, "rb");
	if (!data_bio) {
		result = VERIFY_ERR_OPEN_FILE;
		goto cleanup;
	}

	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		result = VERIFY_ERR_MEM;
		goto cleanup;
	}
	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) !=
	    1) {
		result = VERIFY_ERR_SIG_VERIFY;
		goto cleanup;
	}

	char buf[4096];
	int readlen;
	while ((readlen = BIO_read(data_bio, buf, sizeof(buf))) > 0) {
		if (EVP_DigestVerifyUpdate(mdctx, buf, readlen) != 1) {
			result = VERIFY_ERR_HASH;
			goto cleanup;
		}
	}
	if (readlen < 0) {
		result = VERIFY_ERR_HASH;
		goto cleanup;
	}

	if (EVP_DigestVerifyFinal(mdctx, sigbuf, siglen) == 1) {
		result = VERIFY_OK;
	} else {
		result = VERIFY_ERR_SIG_VERIFY;
		if (errbuf)
			snprintf(errbuf, errbuf_len,
				 "Signature verification failed "
				 "(key type %s, sig len %ld)",
				 key_name, siglen);
	}

cleanup:
	if (sigbuf) {
		OPENSSL_cleanse(sigbuf, siglen);
		free(sigbuf);
	}
	if (data_buf) {
		OPENSSL_cleanse(data_buf, data_len);
		free(data_buf);
	}
	if (fp)
		fclose(fp);
	if (mdctx)
		EVP_MD_CTX_free(mdctx);
	if (data_bio)
		BIO_free(data_bio);
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (ctx)
		X509_STORE_CTX_free(ctx);
	if (store)
		X509_STORE_free(store);
	if (signer_cert)
		X509_free(signer_cert);

	if (result != VERIFY_OK && errbuf && !errbuf[0])
		format_openssl_errors(errbuf, errbuf_len);

	return result;
}

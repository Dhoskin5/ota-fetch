#include "verify_libcrypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
static void format_openssl_error(char *errbuf, size_t len) {
	if (errbuf && len > 0) {
		unsigned long err = ERR_peek_last_error();
		ERR_error_string_n(err, errbuf, len);
	}
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
	long siglen = 0;
	verify_result_t result = VERIFY_ERR_UNKNOWN;

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
	if (X509_STORE_load_locations(store, ca_path, NULL) != 1) {
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

	// --- Open manifest data file as BIO ---
	data_bio = BIO_new_file(data_path, "rb");
	if (!data_bio) {
		result = VERIFY_ERR_OPEN_FILE;
		goto cleanup;
	}

	// --- Prepare for verification (SHA-256 by default) ---
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

	// --- Stream and hash manifest file, update signature context ---
	char buf[4096];
	int readlen;
	while ((readlen = BIO_read(data_bio, buf, sizeof(buf))) > 0) {
		if (EVP_DigestVerifyUpdate(mdctx, buf, readlen) != 1) {
			result = VERIFY_ERR_HASH;
			goto cleanup;
		}
	}

	// --- Verify the signature ---
	if (EVP_DigestVerifyFinal(mdctx, sigbuf, siglen) == 1) {
		result = VERIFY_OK;
	} else {
		result = VERIFY_ERR_SIG_VERIFY;
		if (errbuf)
			snprintf(errbuf, errbuf_len,
				 "Signature verification failed");
	}

cleanup:
	if (sigbuf) {
		OPENSSL_cleanse(sigbuf, siglen);
		free(sigbuf);
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
		format_openssl_error(errbuf, errbuf_len);

	return result;
}

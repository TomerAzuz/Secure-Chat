#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "api.h"
#include "crypto.h"

char *get_cert_path(const char *username)   {
    const char dir[] = "./keys/clientkeys/";
    const char extension[] = "-cert.pem";
    unsigned long len = strlen(dir) + 2*strlen(username) + strlen(extension) + 2;
    char *path = calloc(len, sizeof(char));
    if(!path)   {
        return NULL;
    }
    snprintf(path, len, "%s%s/%s%s", dir, username, username, extension);
    return path;
}

X509* get_cert(const char path[]) {
    X509 *cert = X509_new();
    if(!cert)   {
        return NULL;
    }
    BIO *bio = BIO_new_file(path, "r");
    if(!bio)    {
        X509_free(cert);
        return NULL;
    }
    PEM_read_bio_X509(bio, &cert, NULL, NULL);
    if(!cert)   {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

int verify_cert(const char *username)   {
    char *path = get_cert_path(username);
    if(!path)   {
        return -1;
    }
    X509 *cert = get_cert(path);
    free(path);
    if(!cert)   {
        return -1;
    }
    const char cacert_path[] = "./keys/clientkeys/ca-cert.pem";
    X509 *cacert = get_cert(cacert_path);

    EVP_PKEY *capubkey = X509_get0_pubkey(cacert);
    if(!capubkey)   {
        X509_free(cert);
        X509_free(cacert);
        return -1;
    }
    if(X509_verify(cert, capubkey) != 1)    {
        X509_free(cert);
        X509_free(cacert);
        return -1;
    }
    X509_NAME *name = X509_get_subject_name(cert);
    if(!name)   {
        X509_free(cert);
        X509_free(cacert);
        return -1;
    }
    int len = X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0);
    char commonname[len+1];
    memset(commonname, '\0', len+1);
    X509_NAME_get_text_by_NID(name, NID_commonName, commonname, len+1);
    if(strncmp(username, commonname, USERNAME_LEN-1) != 0)  {
        X509_free(cert);
        X509_free(cacert);
        return -1;
    }
    X509_free(cert);
    X509_free(cacert);
    return 0;
}

char *get_key_path(const char* username, char *key_type)    {
    const char dir[] = "./keys/clientkeys/";
    const char extension[] = ".pem";
    unsigned long len = strlen(dir) + 2*strlen(username) + strlen(key_type) + strlen(extension) + 3;
    char *path = calloc(len, sizeof(char));
    if(!path)   {
        return NULL;
    }
    snprintf(path, len, "%s%s/%s_%s%s", dir, username, key_type, username, extension);
    return path;
}

int get_pubkey(EVP_PKEY *pubkey, const char *username)    {
    char *pubkey_path = get_key_path(username, "keypub");
    if(!pubkey_path)   {
        return -1;
    }
    FILE *keyfile = fopen(pubkey_path, "r");
    if(!keyfile)    {
        free(pubkey_path);
        return -1;
    }
    RSA *key = PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);
    if(!key) {
        goto cleanup;
    }
    if(EVP_PKEY_assign_RSA(pubkey, key) != 1)    {
        goto cleanup;
    }

    fclose(keyfile);
    free(pubkey_path);
    return 0;

    cleanup:
        fclose(keyfile);
        free(pubkey_path);
        return -1;
}

int get_privkey(EVP_PKEY *privkey, const char *username) {
    char *privkey_path = get_key_path(username, "keypriv");
    if (!privkey_path) {
        return -1;
    }
    FILE *keyfile = fopen(privkey_path, "r");
    if (!keyfile) {
        free(privkey_path);
        return -1;
    }
    RSA *key = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    if (!key) {
        goto cleanup;
    }
    if (EVP_PKEY_assign_RSA(privkey, key) != 1) {
        goto cleanup;
    }

    fclose(keyfile);
    free(privkey_path);
    return 0;

    cleanup:
        fclose(keyfile);
        free(privkey_path);
        return -1;
}

unsigned char *generate_salt()   {
    unsigned char *salt = calloc(SALT_LEN, sizeof(char));
    if(!salt)   {
        return NULL;
    }
    for(int i = 0; i < SALT_LEN; i++)   {
        RAND_bytes(&salt[i], 1);
    }
    salt[SALT_LEN-1] = '\0';
    return salt;
}

int hash_pwd(char *pwd)  {
    unsigned char *hash = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx)    {
        return -1;
    }
    if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto cleanup;
    }
    if(EVP_DigestUpdate(ctx, pwd, strlen(pwd)) != 1)    {
        goto cleanup;
    }
    hash = OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
    if(!hash)  {
        goto cleanup;
    }
    unsigned int len = 0;
    if(EVP_DigestFinal_ex(ctx, hash, &len) != 1)   {
        OPENSSL_free((void*) hash);
        goto cleanup;
    }
    EVP_MD_CTX_free(ctx);

    /* copy hashed password */
    memset(pwd, '\0', PWD_LEN);
    memcpy(pwd, hash, PWD_LEN-1);
    OPENSSL_free((void*) hash);
    return 0;

    cleanup:
        EVP_MD_CTX_free(ctx);
        return -1;
}

int salt_hash_pwd(char* pwd, char *salt) {
    unsigned int salted_pwd_len = strlen(salt) + strlen(pwd) + 1;
    char salted_pwd[salted_pwd_len];
    memset(salted_pwd, '\0', salted_pwd_len);

    memcpy(salted_pwd, pwd, strlen(pwd));
    strncat(salted_pwd, salt, strlen(salt));
    salted_pwd[salted_pwd_len-1] = '\0';

    if(hash_pwd(salted_pwd) != 0) {
        return -1;
    }
    memset(pwd, '\0', PWD_LEN);
    memcpy(pwd, salted_pwd, PWD_LEN-1);
    pwd[PWD_LEN-1] = '\0';
    return 0;
}

int sign_msg(struct api_msg *msg)  {
    assert(msg);
    unsigned siglen;
    unsigned char sig[SIG_LEN];
    memset(sig, '\0', SIG_LEN);

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if(!ctx)    {
        return -1;
    }
    EVP_PKEY *evpkey = EVP_PKEY_new();
    if(!evpkey) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if(get_privkey(evpkey, msg->sender) != 0)    {
        goto cleanup;
    }
    if(EVP_SignInit(ctx, EVP_sha1()) != 1)  {
        goto cleanup;
    }
    if(EVP_SignUpdate(ctx, msg, sizeof(struct api_msg)) != 1)   {
        goto cleanup;
    }
    if(EVP_SignFinal(ctx, sig, &siglen, evpkey) != 1)   {
        goto cleanup;
    }
    memcpy(msg->sig, sig, siglen);
    msg->sig[SIG_LEN-1] = '\0';

    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(ctx);
    return 0;

    cleanup:
        EVP_PKEY_free(evpkey);
        EVP_MD_CTX_free(ctx);
        return -1;
}

int verify_sig(struct api_msg *msg)    {
    if(verify_cert(msg->sender) != 0)   {
        return -1;
    }
    unsigned char sig[SIG_LEN];
    memset(sig, '\0', SIG_LEN);

    memcpy(sig, msg->sig, SIG_LEN - 1);
    memset(msg->sig, '\0', SIG_LEN);

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if(!ctx)    {
        return -1;
    }
    EVP_PKEY *evpkey = EVP_PKEY_new();
    if(get_pubkey(evpkey, msg->sender) != 0)    {
        goto cleanup;
    }
    if(EVP_VerifyInit(ctx, EVP_sha1()) != 1)    {
        fprintf(stderr,"%s", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if(EVP_VerifyUpdate(ctx, msg, sizeof(struct api_msg)) != 1) {
        fprintf(stderr,"%s", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if(EVP_VerifyFinal(ctx, sig, SIG_LEN - 1, evpkey) != 1)  {
        fprintf(stderr,"%s", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    EVP_PKEY_free(evpkey);
    EVP_MD_CTX_free(ctx);
    return 0;

    cleanup:
        EVP_PKEY_free(evpkey);
        EVP_MD_CTX_free(ctx);
        return -1;
}

int generate_rsa_keys(const char *username) {
    const char *path;
    path = "./ttp/gen_client_keys.sh";
    unsigned long len = strlen(path) + strlen(username) + 2;
    char cmd[len];
    memset(cmd, '\0', len);
    snprintf(cmd, len, "%s %s", path, username);
    int r = system(cmd);
    return r;
}

unsigned char* use_rsa(const char *username, const unsigned char *msg, int encrypt)    {
    char *key_type = encrypt ? "keypub" : "keypriv";
    char *path = get_key_path(username, key_type);
    if(!path)   {
        return NULL;
    }
    FILE *file = fopen(path, "r");
    if(!file)   {
        free(path);
        return NULL;
    }
    RSA *key = encrypt ? PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL) :
                        PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
    if(!key)    {
        goto cleanup;
    }
    size_t rsa_size = RSA_size(key);
    unsigned char *outbuf = calloc(rsa_size + 1, sizeof(char));
    if(!outbuf) {
        goto cleanup;
    }
    size_t inlen = strlen((char *) msg);
    if(encrypt && inlen > rsa_size - 42) {
        goto cleanup;
    }
    int r = encrypt ? RSA_public_encrypt(inlen, msg, outbuf,
                                         key,RSA_PKCS1_OAEP_PADDING) :
                      RSA_private_decrypt(rsa_size, msg, outbuf,
                                          key, RSA_PKCS1_OAEP_PADDING);
    if(r == -1) goto cleanup;
    free(path);
    fclose(file);
    return outbuf;

    cleanup:
        free(path);
        fclose(file);
        return NULL;
}

int generate_aes_key(const char *username)  {
    const char path[] = "./ttp/gen_aes.sh";
    unsigned long len = strlen(path) + strlen(username) + 2;
    char cmd[len];
    memset(cmd, '\0', len);
    snprintf(cmd, len, "%s %s", path, username);
    cmd[len-1] = '\0';
    int r = system(cmd);
    if(r != 0)  {
        return -1;
    }
    return 0;
}

    /* extract key and iv from file */
int get_key_and_iv(FILE *file, struct aes_key *aes)    {
    if(!fgets((char*)aes->key, AES_LEN+1, file)) {
        fclose(file);
        return -1;
    }
    if(!fgets((char*)aes->iv, IV_LEN+1, file))  {
        fclose(file);
        return -1;
    }
    aes->key[AES_LEN-1] = '\0';
    aes->iv[IV_LEN-1] = '\0';
    return 0;
}

struct aes_key *get_aes_key(const char *username)   {
    if(generate_aes_key(username) != 0) {
        return NULL;
    }
    const char aes_dir[] = "./keys/clientkeys/aes/aes_";
    const char extension[] = ".txt";
    unsigned long path_len = strlen(aes_dir) + strlen(username) + strlen(extension) + 1;
    char path[path_len];
    memset(path, '\0', path_len);
    snprintf(path, path_len, "%s%s%s", aes_dir, username, extension);

    FILE *file = fopen(path, "r");
    if(!file)   {
        return NULL;
    }
    struct aes_key *aes = calloc(1, sizeof(struct aes_key));
    if(get_key_and_iv(file, aes) != 0)  {
        fclose(file);
        return NULL;
    }
    fclose(file);
    return aes;
}

unsigned char* aes_encrypt(unsigned char *plaintext, struct aes_key *aes)   {
    int len, ciphertext_len;
    unsigned char *ciphertext = calloc(128, 1);
    if(!ciphertext) {
        return NULL;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)    {
        free(ciphertext);
        return NULL;
    }
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes->key, aes->iv) != 1) {
        goto cleanup;
    }
    int plaintext_len = strlen((char*) plaintext);
    if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        goto cleanup;
    }
    ciphertext_len = len;
    if(EVP_EncryptFinal(ctx, ciphertext + len, &len) != 1)  {
        goto cleanup;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len >= 0 ? ciphertext : NULL;

    cleanup:
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
}

unsigned char* aes_decrypt(unsigned char *ciphertext, struct aes_key *aes)  {
    int len, plaintext_len;
    unsigned char *plaintext = calloc(BUFFER_LEN, 1);
    if(!plaintext)  {
        return NULL;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)    {
        free(plaintext);
        return NULL;
    }
    if(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes->key, aes->iv) != 1)  {
        goto cleanup;
    }
    int ciphertext_len = strlen((char*) ciphertext);
    if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)    {
        goto cleanup;
    }
    plaintext_len = len;
    if(EVP_DecryptFinal(ctx, plaintext + len, &len) != 1)   {
        goto cleanup;
    }
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';
    return plaintext_len >= 0 ? plaintext : NULL;

    cleanup:
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
}


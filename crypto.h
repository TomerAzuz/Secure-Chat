#ifndef _CRYPTO_H
#define _CRYPTO_H

#define SALT_LEN    9
#define AES_LEN     65
#define IV_LEN      33

struct aes_key{
    unsigned char key[AES_LEN];
    unsigned char iv[IV_LEN];
};

char *get_cert_path(const char *username);
X509* get_cert(const char path[]);
int salt_hash_pwd(char* pwd, char *salt);
unsigned char *generate_salt();
int hash_pwd(char *pwd);
int sign_msg(struct api_msg *msg);
int verify_sig(struct api_msg *msg);
char *get_key_path(const char* username, char *key_type);
int generate_rsa_keys(const char *username);
unsigned char* use_rsa(const char *username, const unsigned char *msg, int encrypt);
struct aes_key *get_aes_key(const char *username);
unsigned char* aes_encrypt(unsigned char *plaintext, struct aes_key *aes);
unsigned char* aes_decrypt(unsigned char *ciphertext, struct aes_key *aes);

#endif

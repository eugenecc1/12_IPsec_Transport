#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

void aes_gcm_encrypt(const unsigned char *key, unsigned char *pt, int pt_len, unsigned char *aad, int aad_len, unsigned char *iv, int iv_len, unsigned char **ct, int *ct_len, unsigned char **tag, int tag_len)
{
	EVP_CIPHER_CTX *ctx;
	int outlen;
	unsigned char outbuf[1024];
	printf("AES GCM Encrypt:\n");
	ctx = EVP_CIPHER_CTX_new();
	memset(outbuf, 0, 1024);
	
	/* Set cipher type and mode */
	EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv_len), NULL);
	
	/* Initialise key and IV */
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	
	/* Zero or more calls to specify any AAD */
	EVP_EncryptUpdate(ctx, NULL, &outlen, aad, sizeof(aad_len));
	
	/* Encrypt plaintext */
	EVP_EncryptUpdate(ctx, outbuf, &outlen, pt, sizeof(pt_len));
	
        *ct_len = outlen;
	*ct = malloc(outlen);

	memcpy(*ct, &outbuf, outlen);

	/* Get tag */
	EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, outbuf);
	
	*tag = malloc(tag_len);

	memcpy(*tag, &outbuf, tag_len);

	EVP_CIPHER_CTX_free(ctx);
}

uint16_t checksum(uint16_t *data, int len)
{
	int i = len;
	uint32_t sum = 0;
	uint16_t oddbyte = 0;		
	uint16_t chcksum;		

	while (i > 1)  {
		sum += *data++;
		i -= 2;
	}
				
	if (i == 1) {
		*((u_char *) &oddbyte) = *(u_char *)data;   
		sum += oddbyte;
	}

	sum  = (sum >> 16) + (sum & 0xffff);		
	sum += (sum >> 16);				
	chcksum = ~sum;		
	
	return chcksum;
}

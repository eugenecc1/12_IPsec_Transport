//Reference Nick
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <byteswap.h>
#include "data.h"

#define ETH_HEADER 14
#define IP_HEADER 20
#define UDP_HEADER 8
#define BYTE_TAG_12 12
#define BYTE_TAG_16 16
#define ESP_CODE 0x32
#define UDP_CODE 0x11
#define TTL_OFFSET 22
#define PROTO_OFFSET 23
#define LENGTH_OFFSET 16
#define CHECKSUM_OFFSET 24
#define MINTRAILER_SIZE 2
#define PADDING_BUFF_SIZE 5

void frame(const unsigned char key[], const unsigned char salt[], const unsigned char spi[], const unsigned char seq_l[], 
		const unsigned char seq_h[], const unsigned char iv[], const unsigned char pkt[], const unsigned char known_output[],
		int salt_size, int spi_size, int seq_l_size, int seq_h_size, int iv_size, int pkt_size, int tag_size);

int main(void)
{
	
	printf("P2:\n");
	frame(p2_key, p2_salt, p2_spi, p2_seq_l, NULL, p2_iv, p2_pkt, p2_known_output,sizeof(p2_salt), sizeof(p2_spi), sizeof(p2_seq_l), -1, sizeof(p2_iv),sizeof(p2_pkt), BYTE_TAG_12);

	printf("P3:\n");
	frame(p3_key, p3_salt, p3_spi, p3_seq_l, p3_seq_h, p3_iv, p3_pkt, p3_known_output,sizeof(p3_salt), sizeof(p3_spi), sizeof(p3_seq_l), sizeof(p3_seq_h), sizeof(p3_iv),sizeof(p3_pkt), BYTE_TAG_16);

	printf("P5:\n");	
	frame(p5_key, p5_salt, p5_spi, p5_seq_l, NULL, p5_iv, p5_pkt, p5_known_output,sizeof(p5_salt), sizeof(p5_spi), sizeof(p5_seq_l), -1, sizeof(p5_iv),sizeof(p5_pkt), BYTE_TAG_16);
	
	return 0;
	
}

void frame(const unsigned char key[], const unsigned char salt[], const unsigned char spi[], const unsigned char seq_l[], 
		const unsigned char seq_h[], const unsigned char iv[], const unsigned char pkt[], const unsigned char known_output[],
		int salt_size, int spi_size, int seq_l_size, int seq_h_size, int iv_size, int pkt_size, int tag_size)
{
	
	int nonce_size = salt_size + iv_size;
	unsigned char *nonce = malloc(nonce_size);
	
	// Nonce = salt
	memcpy(nonce, salt, salt_size);
	
	// Nounce = salt + iv
	memcpy(nonce + salt_size, iv, iv_size);

	int aad_size;
	int esp_Header_size;
	unsigned char *aad, *esp_Header;
	
	if (seq_h)
	{ 
		esp_Header_size = spi_size + seq_l_size;
		esp_Header = malloc(esp_Header_size);
		
		// ESP Header = SPI
		memcpy(esp_Header, spi, spi_size);
		
		//ESP Header = SPI + Sequence_NUmber_Low
		memcpy(esp_Header + spi_size, seq_l, seq_l_size);
		aad_size = esp_Header_size + seq_h_size;
		aad = malloc(aad_size);
		
		//ADD = SPI + Sequence_Number_High + Sequence_Number_Low
		memcpy(aad, spi, spi_size);
		memcpy(aad + spi_size, seq_h, seq_h_size);
		memcpy(aad + spi_size+seq_h_size, seq_l, seq_l_size);
	}
	else
	{
	
		aad_size = spi_size + seq_l_size;
		aad = malloc(aad_size);
	
		//ADD = SPI
		memcpy(aad, spi, spi_size);
	
		//ADD = SPI + Sequence_Number_Low
		memcpy(aad + spi_size, seq_l, seq_l_size);

		esp_Header_size = aad_size;
		esp_Header = aad;
	}
	
	// Ethernet Header = 0 
	unsigned char eth_Header[ETH_HEADER];
	memcpy(eth_Header, pkt, ETH_HEADER);
	
	// IP Header = 0 + 14
	unsigned char ip_Header[IP_HEADER];
	memcpy(ip_Header, pkt + ETH_HEADER, IP_HEADER);
	
	// UDP Payload = packet size - Ethernet Header -IP Header 
	int payloadsize = pkt_size - (ETH_HEADER+IP_HEADER);
	unsigned char *payload = malloc(payloadsize);
	
	// Payload = 0 + 14 +  20
	memcpy(payload, pkt + ETH_HEADER + IP_HEADER, payloadsize);

	unsigned char esptrailer[PADDING_BUFF_SIZE];
	int paddingBytes = 0;

	while(1)
	{
		if ((payloadsize + MINTRAILER_SIZE + paddingBytes) % 4 == 0)
		break;
		esptrailer[paddingBytes] = paddingBytes + 1;
		paddingBytes++;
	}
	
	esptrailer[paddingBytes] = paddingBytes;
	esptrailer[paddingBytes + 1] = UDP_CODE;

	int encryptsize = payloadsize + paddingBytes + MINTRAILER_SIZE;
	unsigned char *pt = malloc(encryptsize);
	memcpy(pt, payload, payloadsize);
	memcpy(pt + payloadsize, &esptrailer, paddingBytes + MINTRAILER_SIZE);

	unsigned char *ct, *tag;
	int ct_size;
	aes_gcm_encrypt(key, pt, encryptsize, aad, aad_size, nonce, nonce_size, &ct, &ct_size, &tag, tag_size);
	
	// Total Packet Size
	int PacketSize = ETH_HEADER + IP_HEADER + esp_Header_size + iv_size + ct_size + tag_size;
	unsigned char *Packet = malloc(PacketSize);
	
	memcpy(Packet, eth_Header, ETH_HEADER);
	
	// Packet = Ethernet header
	memcpy(Packet + ETH_HEADER ,ip_Header, IP_HEADER);
	
	// Packet = Ethernet header + IP Header
	memcpy(Packet + ETH_HEADER + IP_HEADER, esp_Header, esp_Header_size);
	
	// Packet = Ethernet Header + IP Header + ESP Header
	memcpy(Packet + ETH_HEADER + IP_HEADER + esp_Header_size, iv, iv_size);
	
	// Packet = Ethernet Header + IP Header + ESP Header + IV
	memcpy(Packet + ETH_HEADER + IP_HEADER + esp_Header_size + iv_size, ct, ct_size);
	
	// Packet = Ethernet Header + IP Header + ESP Header + IV + CT
	memcpy(Packet + ETH_HEADER + IP_HEADER + esp_Header_size + iv_size + ct_size, tag, tag_size);
	
	uint8_t ttl, proto;
	uint16_t ipTotalLen, checksum_i;
	
	memcpy(&ttl, Packet + TTL_OFFSET, 1);
	
	ttl -= 1;
	
	checksum_i = 0;
	
	proto = ESP_CODE;
	
	ipTotalLen = __bswap_16(PacketSize - ETH_HEADER);
	
	memcpy(Packet + TTL_OFFSET, &ttl, 1); 
	
	memcpy(Packet + PROTO_OFFSET, &proto, 1); 
	
	memcpy(Packet + LENGTH_OFFSET, &ipTotalLen, 2); 
	
	memcpy(Packet + CHECKSUM_OFFSET, &checksum_i, 2); 

	checksum_i = checksum((uint16_t*)(Packet + ETH_HEADER), IP_HEADER); 
	
	memcpy(Packet + CHECKSUM_OFFSET, &checksum_i, 2); 

	if (strcmp(Packet + ETH_HEADER, known_output+ETH_HEADER) == 0)
	{
		printf("PASS\n");
	}
	else
	{
		printf("FAIL\n");
	}

	if (aad_size != esp_Header_size) free(esp_Header); 
	
	free(aad);
	free(nonce);
	free(payload);
	free(pt);
	free(Packet);
	free(ct);
	free(tag);
}





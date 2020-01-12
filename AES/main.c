#define _CRT_SECURE_NO_WARNINGS
#include "aes.h"

void print_hex(char* msg) {
	for (int i = 0; i < 16; i++)
		printf("%02x", (unsigned char)*(msg + i));	
}

void encrypt()
{
	printf("str:");
	char message[128];
	setbuf(stdin, 0);
	fgets(message, 128, stdin);
	message[strlen(message) - 1] = '\0';
	int str_len = strlen((const char*)message);
	int padded_str_len = str_len;
	if (padded_str_len % 16 != 0)
		padded_str_len = (padded_str_len / 16 + 1) * 16;
	unsigned char* padded_str;
	padded_str = (unsigned char*)malloc(padded_str_len * sizeof(unsigned char));
	for (int i = 0; i < padded_str_len; i++) {
		if (i >= str_len) padded_str[i] = 0;
		else padded_str[i] = message[i];
	}

	printf("key:");
	char aes_key[16];
	setbuf(stdin, 0);
	fgets(aes_key, 16, stdin);
	aes_key[strlen(aes_key) - 1] = '\0';
	int key_len = strlen((const char*)aes_key);
	int padded_key_len = key_len;
	if (padded_key_len % 16 != 0)
		padded_key_len = (padded_key_len / 16 + 1) * 16;
	unsigned char* padded_key;
	padded_key = (unsigned char*)malloc(padded_key_len * sizeof(unsigned char));
	for (int i = 0; i < padded_key_len; i++) {
		if (i >= key_len) padded_key[i] = 0;
		else padded_key[i] = aes_key[i];
	}	
	unsigned char expanded_key[176];
	key_expansion(padded_key, expanded_key);

	printf("out:");
	char* enc_msg;
	for (int i = 0; i < padded_str_len; i += 16) {
		enc_msg = aes_encrypt(padded_str + i, expanded_key);
		print_hex(enc_msg);
		free(enc_msg);
	}	
	putchar('\n');
}

void decrypt()
{
	printf("str:");
	char message[255];
	setbuf(stdin, 0);
	fgets(message, 255, stdin);
	message[strlen(message) - 1] = '\0';
	int i = 0;
	int used = 0;
	char messagedec[255];
	while ((sscanf(message + used, "%02x", &messagedec[i])) == 1)
	{
		i++;
		used += 2;
	}
	int str_len = strlen((const char*)messagedec);

	printf("key:");
	char aes_key[16];
	setbuf(stdin, 0);
	fgets(aes_key, 16, stdin);
	aes_key[strlen(aes_key) - 1] = '\0';
	int key_len = strlen((const char*)aes_key);
	int padded_key_len = key_len;
	if (padded_key_len % 16 != 0)
		padded_key_len = (padded_key_len / 16 + 1) * 16;
	unsigned char* padded_key;
	padded_key = (unsigned char*)malloc(padded_key_len * sizeof(unsigned char));
	for (int i = 0; i < padded_key_len; i++) {
		if (i >= key_len) padded_key[i] = 0;
		else padded_key[i] = aes_key[i];
	}
	unsigned char expanded_key[176];
	key_expansion(padded_key, expanded_key);

	printf("out:");
	char* dec_msg;
	for (int i = 0; i < str_len; i += 16) {
		dec_msg = aes_decrypt(messagedec + i, expanded_key);
		printf("%s", dec_msg);
		free(dec_msg);
	}
	putchar('\n');
}

int main()
{
	int choise;
	bool enabled = true;
	while (enabled) {

		printf("choise 1 to encrypt\nchoise 2 to decrypt\nchoise 3 to exit\n");
		printf("choise: ");
		scanf("%d", &choise);
		switch (choise) {
		case 1:
			encrypt();
			break;
		case 2:
			decrypt();
			break;
		case 3:
			enabled = false;
			break;
		default:
			printf("Invalid Option\n");
			break;
		}

	}

	return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libpq-fe.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAX_OPTIONS			4
#define MAX_OPTION_SIZE		50
#define MAX_USER_INPUT_LEN	50
#define MAX_BUF_SIZE		4096

#define ADD_USER			0
#define ADD_FRIEND			1
#define SEND_MSG			2
#define READ_MSG			3

/*
 * Instead of including header file from PG source
 * we can hard code these
 * This will add build time dependency on PG Source
 * Also we do not want PG to infer types
 */
#define VARCHAROID			1043
#define BYTEAOID			17
#define INT4OID				23
#define TIMESTAMPTZOID		1184

/*
 * Global Data
 */
PGconn		*g_conn = NULL;
char		*g_userInput = NULL;


void
closeDbConnection()
{
	if (g_conn == NULL)
		return;
	PQfinish(g_conn);
	g_conn = NULL;
}

void
pq_clear(PGresult **pres)
{
	if (*pres == NULL)
		return;
	PQclear(*pres);
	*pres = NULL;
}

char *getUserInput(char *inputMsg)
{
	size_t bufsize = MAX_USER_INPUT_LEN;
	int characters;

	if (g_userInput == NULL)
	{
		g_userInput = (char *)malloc(MAX_USER_INPUT_LEN + 1);
		if (g_userInput == NULL)
		{
			fprintf(stdout, "\n%s", "Memory Error");
			return NULL;
		}
	}

	memset(g_userInput, 0, sizeof(g_userInput));

	fprintf(stdout, "\n%s", inputMsg);
	characters = getline(&g_userInput, &bufsize, stdin);

	characters--;
	g_userInput[characters] = 0;

	// printf("\n[%s][%d][%d][%s]\n", __FUNCTION__, __LINE__, characters, g_userInput);

	return(g_userInput);
}

int genKeyPair(char *keyName, char **pubKey)
{
	int ret = 0;
	RSA *keyPair = NULL;
	BIGNUM *publicExponent = NULL;
	int keywidth = 2048;
	unsigned long exponentValue = RSA_F4;
	BIO *privateKey = NULL;
	BIO *publicKey = NULL;
	char keyFileName[MAX_BUF_SIZE];

	if (keyName == NULL)
		return 0;

	*pubKey = NULL;

	// 1. Allocate a big number
	publicExponent = BN_new();
	if (publicExponent == NULL)
	{
		return 0;
	}

	// 2. Save RSA_F4 as the value to be used for public exponent in the big number
	//    Any number can be specified, but it is recomended to use RSA_F4 or RSA_3
	ret = BN_set_word(publicExponent, exponentValue);
	if (ret != 1)
	{
		BN_free(publicExponent);
		return 0;
	}

	// 3. Allocate an RSA object
	keyPair = RSA_new();
	if (keyPair == NULL)
	{
		BN_free(publicExponent);
		return 0;
	}

	// 4. Generate RSA keypair
	ret = RSA_generate_key_ex(keyPair, keywidth, publicExponent, NULL);
	if(ret != 1)
	{
		RSA_free(keyPair);
		BN_free(publicExponent);
		return 0;
	}

	// 5. Generate private key file name
	strcpy(keyFileName, "/tmp/");
	strcat(keyFileName, keyName);
	strcat(keyFileName, "_private");
	strcat(keyFileName, ".pem");

	// 6. Allocate file to store private key
	privateKey = BIO_new_file(keyFileName, "w+");
	if (privateKey == NULL)
	{
		RSA_free(keyPair);
		BN_free(publicExponent);
		return 0;
	}
	// 7. Save private key in key file, without using password
	ret = PEM_write_bio_RSAPrivateKey(privateKey, keyPair, NULL, NULL, 0, NULL, NULL);
	if (ret != 1)
	{
		BIO_free_all(privateKey);
		RSA_free(keyPair);
		BN_free(publicExponent);
		return 0;
	}

	// 8. Generate public key file name
	strcpy(keyFileName, "/tmp/");
	strcat(keyFileName, keyName);
	strcat(keyFileName, "_public");
	strcat(keyFileName, ".pem");

	// 9. Allocate file to store public key
	publicKey = BIO_new_file(keyFileName, "w+");
	if (publicKey == NULL)
	{
		BIO_free_all(privateKey);
		RSA_free(keyPair);
		BN_free(publicExponent);
		return 0;
	}

	// 10. Save public key in key file
	ret = PEM_write_bio_RSAPublicKey(publicKey, keyPair);
	BIO_free_all(publicKey);
	if (ret != 1)
	{
		BIO_free_all(privateKey);
		RSA_free(keyPair);
		BN_free(publicExponent);
		return 0;
	}

	// 11. Allocate public key BIO buffer
	publicKey = BIO_new(BIO_s_mem());
	if (publicKey == NULL)
	{
		BIO_free_all(privateKey);
		RSA_free(keyPair);
		BN_free(publicExponent);
		return 0;
	}

	// 12. Read public key from RSA key pair and write to BIO
	ret = PEM_write_bio_RSAPublicKey(publicKey, keyPair);
	if (ret != 1)
	{
		BIO_free_all(publicKey);
		BIO_free_all(privateKey);
		RSA_free(keyPair);
		BN_free(publicExponent);
		return 0;
	}

	// 13. Get the length of the public key in BIO
	size_t publicKeyLength = BIO_pending(publicKey);

	// 14. Allocate public key buffer
	*pubKey = (char *)malloc(publicKeyLength + 1);

	// 15. Read public key from BIO to buffer
	ret = BIO_read(publicKey, (void *)*pubKey, publicKeyLength);
	if (ret != publicKeyLength)
	{
		free(*pubKey);
		*pubKey = NULL;
		BIO_free_all(publicKey);
		BIO_free_all(privateKey);
		RSA_free(keyPair);
		BN_free(publicExponent);
		return 0;
	}

	BIO_free_all(publicKey);
	BIO_free_all(privateKey);
	RSA_free(keyPair);
	BN_free(publicExponent);
	// 16. Return public key length
	return ret;
}

int addUser()
{
	PGresult *res = NULL;
	char *userName;
	char *userPublicKey = NULL;
	const char *SQL = "INSERT INTO pmea.tbl_users(u_name, u_public_key) VALUES($1,$2)";
	int nParams = 2;
	const int paramFormats[] = {0, 0};	// 0: varchar 1: binary
	const Oid paramTypes[] = {VARCHAROID, VARCHAROID};
	int paramLengths[] = {0, 0};
	char *paramValues[2];
	int resultFormat = 0;
	int count = 0;
	int pubKeyLen;

	res = PQprepare(g_conn, "", SQL, nParams, paramTypes);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		fprintf(stderr, "\nPrepare for Insert [%s] failed", SQL);
		return 0;
	}
	pq_clear(&res);

	while (1)
	{
		// a) Select a username.
		userName = getUserInput("Enter your desired username (q to quit):");
		if (strlen(userName) <= 1)
		{
			return count;
		}

		// printf("\n[%s][%d][%s]\n", __FUNCTION__, __LINE__, userName);

		// d) Generate a public-private key pair.
		// e) Store the private key in the keyfile.
		pubKeyLen = genKeyPair(userName, &userPublicKey);
		if (pubKeyLen <= 0)
			return count;

//		paramLengths[1] = pubKeyLen;

		paramValues[0] = userName;
		paramValues[1] = userPublicKey;

		// f) Insert the new user in the table tbl_users.
		res = PQexecPrepared(g_conn, "", nParams,
							(const char * const*)paramValues,
							paramLengths, paramFormats, resultFormat);
		free(userPublicKey);
		if (PQresultStatus(res) != PGRES_COMMAND_OK)
		{
			fprintf(stderr, "\nPQexecPrepared failed for Insert [%s]", SQL);
			return 0;
		}
		pq_clear(&res);
		count++;
	}
	return count;
}

int getUserID(char *username)
{
	int userID = 0;
	char SQL[MAX_BUF_SIZE];
	PGresult *res = NULL;

	if (username == NULL)
		return -1;

	strcpy(SQL, "SELECT u_id FROM pmea.tbl_users WHERE u_name = '");
	strcat(SQL, username);
	strcat(SQL, "';");

	res = PQexec(g_conn, SQL);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		pq_clear(&res);
		return -1;
	}
	if ( (PQntuples(res) != 1) || (PQnfields(res) != 1) )
	{
		pq_clear(&res);
		return -1;
	}
	userID = atoi(PQgetvalue(res, 0, 0));
	pq_clear(&res);
	return userID;
}

int getUserKeyPair(char *username, RSA **privKey, RSA **pubKey)
{
	BIO *pubKeyFile = NULL;
	BIO *privKeyFile = NULL;
	char keyFileName[MAX_BUF_SIZE];
	int ret;

	if (username == NULL)
		return 0;

	// 1. Generate public key file name
	strcpy(keyFileName, "/tmp/");
	strcat(keyFileName, username);
	strcat(keyFileName, "_public");
	strcat(keyFileName, ".pem");

	// 2. Allocate file for reading public key
	pubKeyFile = BIO_new(BIO_s_file());
	if (pubKeyFile == NULL)
	{
		return 0;
	}

	// 3. Read public key in buffer
	ret = BIO_read_filename(pubKeyFile, keyFileName);
	if (ret != 1)
	{
		BIO_free_all(pubKeyFile);
		return 0;
	}

	// 5. Read public key in RSA structure
	*pubKey = PEM_read_bio_RSAPublicKey(pubKeyFile, NULL, NULL, NULL);
	BIO_free_all(pubKeyFile);
	if (ret != 1)
	{
		return 0;
	}

	// 6. Generate private key file name
	strcpy(keyFileName, "/tmp/");
	strcat(keyFileName, username);
	strcat(keyFileName, "_private");
	strcat(keyFileName, ".pem");

	// 7. Allocate file for reading private key
	privKeyFile = BIO_new(BIO_s_file());
	if (privKeyFile == NULL)
	{
		RSA_free(*pubKey);
		return 0;
	}

	// 8. Read private key in buffer
	ret = BIO_read_filename(privKeyFile, keyFileName);
	if (ret != 1)
	{
		BIO_free_all(privKeyFile);
		RSA_free(*pubKey);
		return 0;
	}

	// 9. Read private key in RSA structure
	*privKey = PEM_read_bio_RSAPrivateKey(privKeyFile, NULL, NULL, NULL);
	BIO_free_all(privKeyFile);
	if (ret != 1)
	{
		RSA_free(*pubKey);
		return 0;
	}
	return 1;
}

char *rightPad(char *inp, int num, char toPad)
{
	char buf[2];
	int i;

	buf[0] = toPad;
	buf[1] = '\0';
	for (i = 0; i < num; i++)
	{
		strcat(inp, buf);
	}
	return inp;
}

int createRSAKeyFromBuf(unsigned char *keyBuf, int public, RSA **rsaKey)
{
	BIO *key;
	
	if (keyBuf == NULL)
		return 0;
	
	key = BIO_new_mem_buf(keyBuf, -1);
	if (key == NULL)
	{
		return 0;
	}
	if (public)
	{
		*rsaKey = PEM_read_bio_RSAPublicKey(key, NULL, NULL, NULL);
	}
	else
	{
		*rsaKey = PEM_read_bio_RSAPrivateKey(key, NULL, NULL, NULL);
	}
	BIO_free_all(key);
	if(*rsaKey == NULL)
	{
		return 0;
	}
	return 1;
}

int genSecretKey(unsigned char *key, unsigned char *iv)
{
	unsigned char salt[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
	unsigned int seed = 0x00beef00;
	unsigned char rand_data[16];
	int rand_data_len;
	int ret;
	int nrounds = 5;
	
	if (key == NULL || iv == NULL)
		return 0;

	RAND_seed(&seed, sizeof(seed));
	RAND_bytes(rand_data, sizeof(rand_data));
	rand_data_len = sizeof(rand_data);

	ret = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, rand_data, rand_data_len, nrounds, key, iv);
	if (ret != 32)
	{
		printf("Key size is %d bits - should be 256 bits\n", ret);
		return 0;
	}
	return 1;
}

int addFriend()
{
	char *username;
	RSA *userPubKey = NULL;
	RSA *userPrivKey = NULL;
	RSA *friendPubKey = NULL;
	int ret;
	PGresult *res = NULL;
	int i;
	char row[MAX_BUF_SIZE + 1];
	char col1Val[MAX_BUF_SIZE + 1];
	char query[MAX_BUF_SIZE + 1];
	int count = 0;
	int fid = 0;
	const char *SQL = "INSERT INTO pmea.tbl_friends(f_from_u_id, f_to_u_id, f_mek_for_sending, f_mek_for_reading) VALUES($1, $2, $3, $4)";
	char *friendID;
	unsigned char *mekForSending = NULL;
	unsigned char *mekForReading = NULL;
	int mekForSendingSize;
	int mekForReadingSize;
	int nParams = 4;
	const int paramFormats[] = {0, 0, 1, 1};
	const Oid paramTypes[] = {INT4OID, INT4OID, BYTEAOID, BYTEAOID};
	int paramLengths[] = {0, 0, 1, 1};
	char *paramValues[4];
	int resultFormat = 1;
	char uid[MAX_USER_INPUT_LEN + 1];
	unsigned char key[32], iv[32];
	unsigned char key_iv[64];

	// a) Enter username.
	username = getUserInput("Enter your username (q to quit):");
	if (strlen(username) <= 1)
		return 0;

	// d) Confirm username exists in tbl_users.
	int myUserID = getUserID(username);
	if (myUserID <= 0)
		return 0;

	memset(uid, 0, MAX_USER_INPUT_LEN + 1);
	snprintf(uid, MAX_USER_INPUT_LEN, "%d", myUserID);

	// b) Enter keystore password.
	// c) Enter key password.
	// e) Load public-private key pair from keystore.
	ret = getUserKeyPair(username, &userPrivKey, &userPubKey);
	if (ret <= 0)
		return 0;

	// User's private key is not required in this function
	if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }

	mekForSendingSize = RSA_size(userPubKey);
	mekForSending = (unsigned char *)malloc(mekForSendingSize);

	// f) List available users.
	printf("Available Users:\n");
	printf("  ID     |    Username\n");
	printf("---------+------------\n");

	memset(query, 0, MAX_BUF_SIZE + 1);
	snprintf(query, MAX_BUF_SIZE, "%s%d%s",
			"SELECT u_id, u_name FROM pmea.tbl_users WHERE u_id != ",
			myUserID,
			" ORDER BY u_id;");

	res = PQexec(g_conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		if (userPubKey != NULL) { RSA_free(userPubKey); userPubKey = NULL; }
		if (friendPubKey != NULL) { RSA_free(friendPubKey); friendPubKey = NULL; }
		pq_clear(&res);
		return -1;
	}
	for (i = 0; i < PQntuples(res); i++)
	{
		memset(row, 0, MAX_BUF_SIZE + 1);
		memset(col1Val, 0, MAX_BUF_SIZE + 1);
		snprintf(col1Val, MAX_BUF_SIZE, "%s", PQgetvalue(res, i, 0));
		snprintf(row, MAX_BUF_SIZE, "%s%s%s%s\n",
				"  ",
				rightPad(col1Val, 6, ' '),
				"|  ",
				PQgetvalue(res, i, 1));
		printf(row);
	}
	pq_clear(&res);

	count = 0;

	res = PQprepare(g_conn, "ADD_FRIEND", SQL, nParams, paramTypes);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		fprintf(stderr, "\nPrepare for Insert [%s] failed", SQL);
		return count;
	}
	pq_clear(&res);

	while (1)
	{
		// g) Select a friend.
		friendID = getUserInput("Enter ID of user to make friend (0 to quit):");
		fid = atoi(friendID);
		if (fid == 0)
		{
			break;
		}

		// h) Get friend’s public key from the tbl_users.
		strcpy(query, "SELECT u_public_key FROM pmea.tbl_users WHERE u_id = ");
		strcat(query, friendID);
		strcat(query, ";");

		res = PQexec(g_conn, query);
		if (PQresultStatus(res) != PGRES_TUPLES_OK)
		{
			fprintf(stderr, "\nFailed to get friend public key via query %s", query);
			break;
		}
		if ( (PQntuples(res) != 1) || (PQnfields(res) != 1) )
		{
			fprintf(stderr, "\nInvalid friend public key got via query %s", query);
			break;
		}
		ret = createRSAKeyFromBuf(PQgetvalue(res, 0, 0), 1, &friendPubKey);
		if (ret <= 0)
		{
			fprintf(stderr, "\nFailed to convert friend public key to RSA key");
			break;
		}
		pq_clear(&res);

		// i) Generate a secret key.
		ret = genSecretKey(key, iv);
		if (ret <= 0)
		{
			fprintf(stderr, "\nFailed to generate secret key");
			break;
		}
		memcpy(key_iv, key, 32);
		memcpy(key_iv + 32, iv, 32);

		// j) Encrypt the secret key using your own public key and store in f_mek_for_sending.
		ret = RSA_public_encrypt(sizeof(key_iv), key_iv,
					mekForSending, userPubKey, RSA_PKCS1_OAEP_PADDING);
		if (ret != mekForSendingSize)
		{
			fprintf(stderr, "\nFailed encrypt secret key using user public key");
			break;
		}

		// k) Encrypt the secret key using friend’s public key and store in f_mek_for_reading.
		mekForReadingSize = RSA_size(friendPubKey);
		mekForReading = (unsigned char *)malloc(mekForReadingSize);
		ret = RSA_public_encrypt(sizeof(key_iv), key_iv,
					mekForReading, friendPubKey, RSA_PKCS1_OAEP_PADDING);
		if (ret != mekForReadingSize)
		{
			fprintf(stderr, "\nFailed encrypt secret key using friend public key");
			break;
		}

		// l) Insert row in tbl_friends.
		paramLengths[2] = mekForSendingSize;
		paramLengths[3] = mekForReadingSize;

		paramValues[0] = uid;
		paramValues[1] = friendID;
		paramValues[2] = mekForSending;
		paramValues[3] = mekForReading;

		res = PQexecPrepared(g_conn, "ADD_FRIEND", nParams,
							(const char * const*)paramValues,
							paramLengths, paramFormats, resultFormat);

		if (friendPubKey != NULL) { RSA_free(friendPubKey); friendPubKey = NULL; }
		if (mekForReading != NULL) { free(mekForReading); mekForReading = NULL; }

		if (PQresultStatus(res) != PGRES_COMMAND_OK)
		{
			fprintf(stderr, "\nPQexecPrepared failed for Insert [%s]", SQL);
			break;
		}
		pq_clear(&res);
		count++;
	}

	pq_clear(&res);
	if (userPubKey != NULL) { RSA_free(userPubKey); userPubKey = NULL; }
	if (friendPubKey != NULL) { RSA_free(friendPubKey); friendPubKey = NULL; }
	if (mekForSending != NULL) { free(mekForSending); mekForSending = NULL; }
	if (mekForReading != NULL) { free(mekForReading); mekForReading = NULL; }

	strcpy(query, "DEALLOCATE \"ADD_FRIEND\"");
	res = PQexec(g_conn, query);
	pq_clear(&res);

	return count;
}

int encryptMessage(EVP_CIPHER_CTX *encCtx, unsigned char *plainText, int plainTextLen, unsigned char **cipherText)
{
	int ret;
	int cipherTextLen = plainTextLen + AES_BLOCK_SIZE;
	int finalLen = 0;

	*cipherText = (unsigned char *)malloc(cipherTextLen);

	ret = EVP_EncryptInit_ex(encCtx, NULL, NULL, NULL, NULL);
	if (ret != 1)
	{
		free(*cipherText);
		*cipherText = NULL;
		return 0;
	}

	ret = EVP_EncryptUpdate(encCtx, *cipherText, &cipherTextLen, plainText, plainTextLen);
	if (ret != 1)
	{
		free(*cipherText);
		*cipherText = NULL;
		return 0;
	}

	ret = EVP_EncryptFinal_ex(encCtx, *cipherText + cipherTextLen, &finalLen);
	if (ret != 1)
	{
		free(*cipherText);
		*cipherText = NULL;
		return 0;
	}

	return cipherTextLen + finalLen;
}


int sendMsg()
{
	unsigned char *encMekForSending = NULL;
	int encMekForSendingSize;
	int myUserID;
	char *username;
	char *friendID;
	RSA *userPubKey = NULL;
	RSA *userPrivKey = NULL;
	int ret;
	unsigned char key[32], iv[32];
	unsigned char key_iv[64];
	const char *SQL = "INSERT INTO pmea.tbl_messages(m_f_id, m_message, m_sent_on) VALUES($1, $2, $3)";
	int count = 0;
	int nParams = 3;
	const int paramFormats[] = {0, 1, 0};
	const Oid paramTypes[] = {INT4OID, BYTEAOID, TIMESTAMPTZOID};
	int paramLengths[] = {0, 0, 0};
	char *paramValues[3];
	int resultFormat = 0;
	char *msgToSend;
	EVP_CIPHER_CTX encryptCtx;
	unsigned char *encryptedMsg;
	int encryptedMsgLen;
	char fid[MAX_USER_INPUT_LEN + 1];
	char curTime[MAX_USER_INPUT_LEN + 1];
	char row[MAX_BUF_SIZE + 1];
	char col1Val[MAX_BUF_SIZE + 1];
	char query[MAX_BUF_SIZE + 1];
	PGresult *res = NULL;
	int i;
	char *f_id;
	int nfid = 0;

	// a) Enter username.
	username = getUserInput("Enter your username (q to quit):");
	if (strlen(username) <= 1)
		return 0;

	// d) Confirm username exists in tbl_users.
	myUserID = getUserID(username);
	if (myUserID <= 0)
		return 0;

	// b) Enter keystore password.
	// c) Enter key password.
	// e) Load public-private key pair from keystore.
	ret = getUserKeyPair(username, &userPrivKey, &userPubKey);
	if (ret <= 0)
		return 0;

	// userPubKey is not required in this function
	if (userPubKey != NULL) { RSA_free(userPubKey); userPubKey = NULL; }

	// f) List available friends.
	printf("Available Friends:\n");
	printf("  ID     |    Friend name\n");
	printf("---------+---------------\n");

	memset(query, 0, MAX_BUF_SIZE + 1);
	snprintf(query, MAX_BUF_SIZE, "%s%d%s",
			"SELECT f_to_u_id, u_name FROM pmea.tbl_users, pmea.tbl_friends WHERE u_id = f_to_u_id AND f_from_u_id = ",
			myUserID,
			" ORDER BY 1;");

	res = PQexec(g_conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }
		pq_clear(&res);
		return 0;
	}
	for (i = 0; i < PQntuples(res); i++)
	{
		memset(row, 0, MAX_BUF_SIZE + 1);
		memset(col1Val, 0, MAX_BUF_SIZE + 1);
		snprintf(col1Val, MAX_BUF_SIZE, "%s", PQgetvalue(res, i, 0));
		snprintf(row, MAX_BUF_SIZE, "%s%s%s%s\n",
				"  ",
				rightPad(col1Val, 6, ' '),
				"|  ",
				PQgetvalue(res, i, 1));
		printf(row);
	}
	pq_clear(&res);

	// g) Select a friend to send message to.
	friendID = getUserInput("Enter ID of the friend to send the message to (0 to quit):");
	ret = atoi(friendID);
	if (ret == 0)
	{
		if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }
		pq_clear(&res);
		return 0;
	}

	// h) Get the message encryption key (f_mek_for_sending) from tbl_friends.
	memset(query, 0, MAX_BUF_SIZE + 1);
	snprintf(query, MAX_BUF_SIZE, "%s%d%s%d%s",
			"SELECT f_id, f_mek_for_sending FROM pmea.tbl_friends WHERE f_from_u_id = ",
			myUserID,
			" AND f_to_u_id = ",
			ret,
			";");
	// Must use PQexecParams to get results in binary form
	res = PQexecParams(g_conn, query, 0, NULL, NULL, NULL, NULL, 1);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }
		pq_clear(&res);
		return 0;
	}
	if ( (PQntuples(res) != 1) || (PQnfields(res) != 2) )
	{
		if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }
		pq_clear(&res);
		return 0;
	}
	f_id = PQgetvalue(res, 0, 0);
	nfid = 0;
	nfid = nfid | f_id[0];
	nfid = nfid << 8;
	nfid = nfid | f_id[1];
	nfid = nfid << 8;
	nfid = nfid | f_id[2];
	nfid = nfid << 8;
	nfid = nfid | f_id[3];
	memset(fid, 0, sizeof(fid));
	snprintf(fid, MAX_USER_INPUT_LEN, "%d", nfid);

	encMekForSendingSize = PQgetlength(res, 0, 1);
	encMekForSending = (unsigned char *)malloc(encMekForSendingSize);
	memcpy(encMekForSending, PQgetvalue(res, 0, 1), encMekForSendingSize);
	pq_clear(&res);

	// i) Decrypt f_mek_for_sending using your private key to get secret key.
	ret = RSA_private_decrypt(encMekForSendingSize, encMekForSending,
							key_iv, userPrivKey, RSA_PKCS1_OAEP_PADDING);
	if (ret != 64)
	{
		if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }
		if (encMekForSending != NULL) { free(encMekForSending); encMekForSending = NULL; }
		pq_clear(&res);
		return 0;
	}

	if (encMekForSending != NULL) { free(encMekForSending); encMekForSending = NULL; }
	if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }

	memcpy(key, key_iv, 32);
	memcpy(iv, key_iv + 32, 32);

	// initialize encryption context using key and iv
	EVP_CIPHER_CTX_init(&encryptCtx);
	ret = EVP_EncryptInit_ex(&encryptCtx, EVP_aes_256_cbc(), NULL, key, iv);
	if (ret != 1)
	{
		pq_clear(&res);
		return 0;
	}

	res = PQprepare(g_conn, "SEND_MSG", SQL, nParams, paramTypes);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		fprintf(stderr, "\nPrepare for Insert [%s] failed", SQL);
		pq_clear(&res);
		return 0;
	}
	pq_clear(&res);

	count = 0;

	while (1)
	{
		// j) Enter message to send.
		msgToSend = getUserInput("Enter the message (q to quit):");
		if (strlen(msgToSend) <= 1)
		{
			pq_clear(&res);
			return count;
		}

		// k) Encrypt message using secret key.
		encryptedMsgLen = encryptMessage(&encryptCtx, msgToSend, strlen(msgToSend), &encryptedMsg);
		if (encryptedMsgLen <= 0)
		{
			pq_clear(&res);
			return count;
		}

		// l) Insert row in tbl_messages.
		paramLengths[1] = encryptedMsgLen;

		paramValues[0] = fid;
		paramValues[1] = encryptedMsg;

		time_t tt = time(NULL);
		struct tm tm = *localtime(&tt);
		memset(curTime, 0, sizeof(curTime));
		snprintf(curTime, MAX_USER_INPUT_LEN, "%d-%d-%d %d:%d:%d",
					tm.tm_year + 1900, tm.tm_mon + 1,tm.tm_mday,
					tm.tm_hour, tm.tm_min, tm.tm_sec);
		paramValues[2] = curTime;

		res = PQexecPrepared(g_conn, "SEND_MSG", nParams,
							(const char * const*)paramValues,
							paramLengths, paramFormats, resultFormat);

		if (encryptedMsg != NULL) { free(encryptedMsg); encryptedMsg = NULL; }

		if (PQresultStatus(res) != PGRES_COMMAND_OK)
		{
			fprintf(stderr, "\nPQexecPrepared failed for Insert [%s]", SQL);
			break;
		}
		pq_clear(&res);
		count++;
	}
	
	strcpy(query, "DEALLOCATE \"SEND_MSG\"");
	res = PQexec(g_conn, query);
	pq_clear(&res);

	return count;
}

int decryptMessage(EVP_CIPHER_CTX *decCtx, unsigned char *cipherText, int cipherTextLen, char **plainText)
{
	int plainTextLen = cipherTextLen;
	int finalLen = 0;
	int ret;

	*plainText = malloc(plainTextLen);
	
	memset(*plainText, 0, plainTextLen);

	ret = EVP_DecryptInit_ex(decCtx, NULL, NULL, NULL, NULL);
	if (ret != 1)
	{
		free(*plainText);
		*plainText = NULL;
		return 0;
	}

	ret = EVP_DecryptUpdate(decCtx, *plainText, &plainTextLen, cipherText, cipherTextLen);
	if (ret != 1)
	{
		free(*plainText);
		*plainText = NULL;
		return 0;
	}

	ret = EVP_DecryptFinal_ex(decCtx, *plainText + plainTextLen, &finalLen);
	if (ret != 1)
	{
		free(*plainText);
		*plainText = NULL;
		return 0;
	}

	return plainTextLen + finalLen;
}

int readMsg()
{
	char *username;
	RSA *userPubKey = NULL;
	RSA *userPrivKey = NULL;
	int myUserID;
	int ret;
	char query[MAX_BUF_SIZE + 1];
	PGresult *res = NULL;
	char col1Val[MAX_BUF_SIZE + 1];
	char col2Val[MAX_BUF_SIZE + 1];
	char col3Val[MAX_BUF_SIZE + 1];
	char col4Val[MAX_BUF_SIZE + 1];
	char row[MAX_BUF_SIZE + 1];
	int count = 0;
	int nfid = 0;
	unsigned char *encMekForReading = NULL;
	int encMekForReadingSize;	
	unsigned char key[32], iv[32];
	unsigned char key_iv[64];
	EVP_CIPHER_CTX decryptCtx;
	char *decryptedMsg = NULL;
	int i;
	char *f_id;
	int emsgLen = 0;
	unsigned char *emsg;

	// a) Enter username.
	username = getUserInput("Enter your username (q to quit):");
	if (strlen(username) <= 1)
		return 0;

	// d) Confirm username exists in tbl_users.
	myUserID = getUserID(username);
	if (myUserID <= 0)
		return 0;

	// b) Enter keystore password.
	// c) Enter key password.
	// e) Load public-private key pair from keystore.
	ret = getUserKeyPair(username, &userPrivKey, &userPubKey);
	if (ret <= 0)
		return 0;

	// userPubKey is not required in this function
	if (userPubKey != NULL) { RSA_free(userPubKey); userPubKey = NULL; }

	// f) List available message count from all friends.
	printf("Available Messages:\n");
	printf("  ID     |    Friend name   |  Message Count\n");
	printf("---------+------------------+---------------\n");

	memset(query, 0, MAX_BUF_SIZE + 1);
	snprintf(query, MAX_BUF_SIZE, "%s%d%s",
			"SELECT pmea.getSenderID (m_f_id) sender_id, pmea.getSenderName(m_f_id) sender_name, count(m_f_id) msg_count FROM pmea.tbl_messages WHERE m_f_id IN ( SELECT f_id FROM pmea.tbl_friends WHERE f_to_u_id = ",
			myUserID,
			") GROUP BY m_f_id ORDER BY 2");

	res = PQexec(g_conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }
		pq_clear(&res);
		return 0;
	}
	for (i = 0; i < PQntuples(res); i++)
	{
		memset(row, 0, MAX_BUF_SIZE + 1);
		memset(col1Val, 0, MAX_BUF_SIZE + 1);
		memset(col2Val, 0, MAX_BUF_SIZE + 1);
		snprintf(col1Val, MAX_BUF_SIZE, "%s", PQgetvalue(res, i, 0));
		snprintf(col2Val, MAX_BUF_SIZE, "%s", PQgetvalue(res, i, 1));
		snprintf(row, MAX_BUF_SIZE, "%s%s%s%s%s%s\n",
				"  ",
				rightPad(col1Val, 6, ' '),
				"|  ",
				rightPad(col2Val, 11, ' '),
				"|  ",
				PQgetvalue(res, i, 2));
		printf(row);
	}
	pq_clear(&res);

	count = 0;

	while (1)
	{
		printf("\n\n");

		// g) Select a friend to read messages from.
		char *tmp = getUserInput("Enter ID of the friend to read the message from (0 to quit):");
		ret = atoi(tmp);
		if (ret == 0)
		{
			break;
		}

		// h) Get the message encryption key (f_mek_for_reading) from tbl_friends.		
		memset(query, 0, MAX_BUF_SIZE + 1);
		snprintf(query, MAX_BUF_SIZE, "%s%d%s%d%s",
				"SELECT f_id, f_mek_for_reading FROM pmea.tbl_friends WHERE f_to_u_id = ",
				myUserID,
				" AND f_from_u_id = ",
				ret,
				";");				
				
		// Must use PQexecParams to get results in binary form
		res = PQexecParams(g_conn, query, 0, NULL, NULL, NULL, NULL, 1);
		if (PQresultStatus(res) != PGRES_TUPLES_OK)
		{
			break;
		}
		if ( (PQntuples(res) != 1) || (PQnfields(res) != 2) )
		{
			break;
		}
		f_id = PQgetvalue(res, 0, 0);
		nfid = 0;
		nfid = nfid | f_id[0];
		nfid = nfid << 8;
		nfid = nfid | f_id[1];
		nfid = nfid << 8;
		nfid = nfid | f_id[2];
		nfid = nfid << 8;
		nfid = nfid | f_id[3];

		encMekForReadingSize = PQgetlength(res, 0, 1);
		encMekForReading = (unsigned char *)malloc(encMekForReadingSize);
		memcpy(encMekForReading, PQgetvalue(res, 0, 1), encMekForReadingSize);
		pq_clear(&res);

		// i) Decrypt  f_mek_for_reading using your private key to get secret key.
		ret = RSA_private_decrypt(encMekForReadingSize, encMekForReading,
								key_iv, userPrivKey, RSA_PKCS1_OAEP_PADDING);
		if (ret != 64)
		{
			break;
		}

		if (encMekForReading != NULL) { free(encMekForReading); encMekForReading = NULL; }

		memcpy(key, key_iv, 32);
		memcpy(iv, key_iv + 32, 32);

		// initialize encryption context using key and iv
		EVP_CIPHER_CTX_init(&decryptCtx);
		ret = EVP_DecryptInit_ex(&decryptCtx, EVP_aes_256_cbc(), NULL, key, iv);
		if (ret != 1)
		{
			break;
		}

		// j) List all messages from the selected friend by decrypting the messages using secret key.
		printf("Messages:\n");
		printf("  ID   |   Friend Name    |    Sent On                  |    Message   \n");
		printf("-------+------------------+-----------------------------+------------------------------------\n");

		memset(query, 0, MAX_BUF_SIZE + 1);
		snprintf(query, MAX_BUF_SIZE, "%s%d%s",
				"SELECT m_id, pmea.getSenderName(m_f_id), m_sent_on, m_message FROM pmea.tbl_messages WHERE m_f_id = ",
				nfid,
				";");

		res = PQexec(g_conn, query);

		// Must use PQexecParams to get results in binary form
//		res = PQexecParams(g_conn, query, 0, NULL, NULL, NULL, NULL, 1);
		if (PQresultStatus(res) != PGRES_TUPLES_OK)
		{
			break;
		}

		for (i = 0; i < PQntuples(res); i++)
		{
			count++;
			memset(row, 0, MAX_BUF_SIZE + 1);
			memset(col1Val, 0, MAX_BUF_SIZE + 1);
			memset(col2Val, 0, MAX_BUF_SIZE + 1);
			memset(col3Val, 0, MAX_BUF_SIZE + 1);
			memset(col4Val, 0, MAX_BUF_SIZE + 1);

			snprintf(col1Val, MAX_BUF_SIZE, "%s", PQgetvalue(res, i, 0));
			snprintf(col2Val, MAX_BUF_SIZE, "%s", PQgetvalue(res, i, 1));
			snprintf(col3Val, MAX_BUF_SIZE, "%s", PQgetvalue(res, i, 2));
			snprintf(col4Val, MAX_BUF_SIZE, "%s", PQgetvalue(res, i, 3));
			emsgLen = 0;
			emsg = PQunescapeBytea(col4Val, (size_t *)&emsgLen);
			if (emsg == NULL)
			{
				break;
			}

			ret = decryptMessage(&decryptCtx, emsg, emsgLen, &decryptedMsg);
			PQfreemem(emsg);
			if (ret <= 0)
			{
				break;
			}
			decryptedMsg[ret] = 0;

			snprintf(row, MAX_BUF_SIZE, "%s%s%s%s%s%s%s%s\n",
					"  ",
					rightPad(col1Val, 4, ' '),
					"|  ",
					rightPad(col2Val, 11, ' '),
					"|  ",
					rightPad(col3Val, 5, ' '),
					"|  ",
					decryptedMsg);
			printf(row);
			if (decryptedMsg != NULL) { free(decryptedMsg); decryptedMsg = NULL; }
		}
		pq_clear(&res);
	}
	if (userPrivKey != NULL) { RSA_free(userPrivKey); userPrivKey = NULL; }
	if (encMekForReading != NULL) { free(encMekForReading); encMekForReading = NULL; }
	if (decryptedMsg != NULL) { free(decryptedMsg); decryptedMsg = NULL; }
	pq_clear(&res);
	return count;
}

int
main(int argc, char **argv)
{
    const char *conninfo = "host = 127.0.0.1 port = 5432 dbname = test_db";
    int			optionIndex;
	int			count;

	char options[MAX_OPTIONS][MAX_OPTION_SIZE] = {"add-user", "add-friend", "send-messages", "read-messages"};

	if (argc < 2)
	{
		fprintf(stderr, "\nThe program expects either add-user, add-friend, send-messages or read-messages as command line argument\n");
		return 0;
	}

	for (optionIndex = 0; optionIndex < MAX_OPTIONS; optionIndex++)
	{
		if (strcmp(argv[1], options[optionIndex]) == 0)
			break;
	}
	if (optionIndex >= MAX_OPTIONS)
	{
		fprintf(stderr, "\nThe program expects either add-user, add-friend, send-messages or read-messages as command line argument\n");
		return 0;
	}

    g_conn = PQconnectdb(conninfo);
    if (PQstatus(g_conn) != CONNECTION_OK)
    {
        fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(g_conn));
        closeDbConnection();
        return 0;
    }

	fprintf(stdout, "\nConnected to %s\n", conninfo);

	count = 0;

	switch (optionIndex)
	{
		case ADD_USER:
			count = addUser();
			fprintf(stdout, "\nAdded %d users\n", count);
		break;
		case ADD_FRIEND:
			count = addFriend();
			fprintf(stdout, "\nAdded %d friends\n", count);
		break;
		case SEND_MSG:
			count = sendMsg();
			fprintf(stdout, "\nSent %d messages\n", count);
		break;
		case READ_MSG:
			count = readMsg();
			fprintf(stdout, "\nRead %d messages\n", count);			
		break;
	}
	closeDbConnection();
    return 0;
}

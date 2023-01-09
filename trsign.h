#ifndef TRSIGN_H
#define TRSIGN_H value

#include "rsign.h"
#include "parameters.h"
#include "stdint.h"

// #define TRSIG_TAG(sig) (sig) 
// #define TRSIG_SALT(sig) (TRSIG_TAG(sig) + PK_BYTES )
// #define TRSIG_CHALLENGE(sig) (TRSIG_SALT(sig) + HASH_BYTES)
// #define TRSIG_B(sig) (TRSIG_CHALLENGE(sig) + SEED_BYTES)
// #define TRSIG_Z(sig) (TRSIG_B(sig) + S1_BYTES)
// #define TRSIG_COMMITMENT_RANDOMNESS(sig) (TRSIG_Z(sig) + S3_BYTES*ZEROS)
// #define TRSIG_PATHS(sig) (TRSIG_COMMITMENT_RANDOMNESS(sig) + SEED_BYTES*ZEROS)
// #define TRSIG_SEEDS(sig, logN) (TRSIG_PATHS(sig) + logN*HASH_BYTES*ZEROS*2 )
// #define TRSIG_BYTES(logN) (TRSIG_SEEDS(0,logN) + SEED_BYTES*ONES)


#define TRSIG_SALT(sig) (sig)
#define TRSIG_CHALLENGE(sig) (TRSIG_SALT(sig) + HASH_BYTES)
#define TRSIG_Z(sig) (TRSIG_CHALLENGE(sig) + SEED_BYTES)
#define TRSIG_COMMITMENT_RANDOMNESS(sig) (TRSIG_Z(sig) + S3_BYTES*ZEROS)
#define TRSIG_PATHS(sig) (TRSIG_COMMITMENT_RANDOMNESS(sig) + SEED_BYTES*ZEROS)
#define TRSIG_SEEDS(sig, logN) (TRSIG_PATHS(sig) + logN*HASH_BYTES*ZEROS*2 )
#define TRSIG_BYTES(logN) (TRSIG_SEEDS(0,logN) + SEED_BYTES*ONES)

/****************************************************************************
* @brief
* @param[in]  sk			-ǩ����˽Կ
* @param[in]  I				-ǩ���߱�ʶ
* @param[in]  pks			-����Կ�ϼ�
* @param[in]  rings			-����С
* @param[in]  L				-tag
* @param[in]  llen			-tag��С
* @param[in]  m				-��ǩ����Ϣ
* @param[in]  mlen			-��Ϣ��С
* @param[out] sig			-ǩ��ֵ  (salt,T,chall,rsp)
* @param[out] sig_len		-ǩ��ֵ��С
* @return
*****************************************************************************/
int trsign(const unsigned char *sk, const int64_t I, const unsigned char *pks, 
	const int64_t rings, const unsigned char *L, uint64_t llen, const unsigned char *m, uint64_t mlen, unsigned char *sig, uint64_t *sig_len);
    

int  trverify(const unsigned char *pks, const int64_t rings, const unsigned char *L, uint64_t llen, const unsigned char *m, uint64_t mlen, const unsigned char *sig);
#endif

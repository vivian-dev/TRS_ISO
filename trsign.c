#include "trsign.h"
#define DEBUG
#define RINGS  (1<<1) // (1<<3)

#define EXPAND_BUF_LEN (SEED_BYTES*(RINGS+2))


#define FM_ROOTS(fm) fm
#define FM_MESSAGE_HASH(fm) (FM_ROOTS(fm) + HASH_BYTES*EXECUTIONS*2)
#define FM_SALT(fm) (FM_MESSAGE_HASH(fm) + HASH_BYTES)
#define FM_BYTES (FM_SALT(0) + HASH_BYTES)

#define ID_BYTES  8
#define AI_BYTES  ID_BYTES+S1_BYTES
public_key TAG;

void conv(unsigned char* a,uint64_t x,int bytes)
{
	for(int i=0;i<bytes;i++)
	{
		a[i]=(unsigned char)x;
		x=x>>8;
	}
}
/****************************************************************************
* @brief
* @param[in]  sk			-签名者私钥
* @param[in]  I				-签名者标识
* @param[in]  pks			-环公钥合集
* @param[in]  rings			-环大小
* @param[in]  L				-tag
* @param[in]  llen			-tag大小
* @param[in]  m				-待签名消息
* @param[in]  mlen			-消息大小
* @param[out] sig			-签名值  (salt,T,chall,rsp)
* @param[out] sig_len		-签名值大小
* @return
*****************************************************************************/
int trsign(const unsigned char *sk, const int64_t I, const unsigned char *pks, 
	const int64_t rings, const unsigned char *L, uint64_t llen, const unsigned char *m, uint64_t mlen, unsigned char *sig, uint64_t *sig_len){
	if (I >= rings || rings > (((uint64_t) 1) << 32))
		return -1;

	int logN = log_round_up(rings);  //logN=log_2(rings)
	uint64_t rings_round_up = (((uint64_t)1) << logN);
	// printf("0\n");
	GRPELTS2 r[EXECUTIONS];
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		init_grpelt(r[i]);  //大整数初始化，每个r[i]视为大整数
	}

	unsigned char seed_tree[(2*EXECUTIONS-1)*SEED_BYTES];
	unsigned char *seeds = seed_tree + (EXECUTIONS-1)*SEED_BYTES;

	unsigned char seedbuf[SEED_BUF_BYTES];
	unsigned char expand_buf[EXPAND_BUF_LEN];
	unsigned char commitments_x[HASH_BYTES*rings_round_up];
	unsigned char commitments_t[HASH_BYTES * rings_round_up];
	unsigned char commitment_randomness[EXECUTIONS*SEED_BYTES];
	XELT R,Tprime;
	unsigned char fm[FM_BYTES];
	unsigned char fma[HASH_BYTES];
	unsigned char fml[HASH_BYTES];
	unsigned char fmc[HASH_BYTES];    
	unsigned char ai[AI_BYTES+10];
	unsigned char paths_x[HASH_BYTES * EXECUTIONS * logN];
	unsigned char paths_t[HASH_BYTES * EXECUTIONS * logN];

	// generate response
	GRPELTS2 z;
	GRPELTS1L s;
	init_grpelt(z);
	init_grpelt(s);
	sample_S1L(s,sk);   //sk派生s
	//1. compute Tag
	GRPELTS1L a, b, c, d, k;
	public_key T0;
	init_grpelt(a);
	init_grpelt(b);
	init_grpelt(c);
	init_grpelt(d);
	init_grpelt(k);
	unsigned char ID[ID_BYTES]={0};
	HASH(m, mlen, fma); 
	sample_S1L(a, fma); //a=H_S1(M)
	pack_S1(ai, a);
	HASH(L,llen,fml);
	sample_S1L(b,fml);  //b=H_S1(L)
	do_action(&(T0),&X0, b); //T0=H_S1(L)\star S0
#ifdef DEBUG
	printf(" ----(P)T0\n");
	for(int i=0;i<LIMBS;i++)
	{
		printf("%ld ",T0.A.c[i]);
	}
	printf("\n");
#endif	
	conv(ID,I,ID_BYTES);
	memcpy(ai + S1_BYTES, ID, ID_BYTES);
	HASH(ai, AI_BYTES, fmc);
	sample_S1L(c, fmc); //c=H_S1(a,I)
	sub(d, s, c);		//d=sk_I-H_S1(a,I)
	do_action(&TAG,&T0, d); //TAG=(sk_I-H_S1(a,I))\star T_0
#ifdef DEBUG
	printf(" ----(P)TAG\n");
	for(int i=0;i<LIMBS;i++)
	{
		printf("%ld ",TAG.A.c[i]);
	}
	printf("\n");
#endif
	//memcpy(TRSIG_TAG(sig),TAG_CHAR,PK_BYTES); //-------------------------- TRSIG_TAG(sig) <--- TAG
			
	// printf("1\n");
	//2.T_i 
	public_key T[RINGS];
	for (int64_t i = 0; i < rings; ++i)
	{
		conv(ID,i,ID_BYTES);
		memcpy(ai + S1_BYTES, ID, ID_BYTES);
		HASH(ai, AI_BYTES, fmc);
		sample_S1L(k, fmc);			//k=H_S1(a,i)

		do_action(&(T[i]),&TAG, k); //T_i=k \star TAG
		#ifdef DEBUG
			printf(" ----(P)Ti[%d]\n",i);
			for(int j=0;j<LIMBS;j++)
			{
				printf("%ld ",T[i].A.c[j]);
			}
			printf("\n");
		#endif
	}
	//P_1_main
	// choose salt
	RAND_bytes(TRSIG_SALT(sig),HASH_BYTES);		//----------------------------------TRSIG_SALT(sig)<--(salt)

	// copy salt  
	memcpy(FM_SALT(fm), TRSIG_SALT(sig), HASH_BYTES);
	memcpy(seedbuf + SEED_BYTES, TRSIG_SALT(sig), HASH_BYTES);
	uint32_t *ctr = (uint32_t *) (seedbuf + HASH_BYTES + SEED_BYTES);

	unsigned char zero_seed[SEED_BYTES] = {0};
	// pick random seeds
	restart: generate_seed_tree(seed_tree,EXECUTIONS,TRSIG_SALT(sig));//在salt作用下生成seed_tree(seed1,...seedM)

	// hash message
	memcpy(FM_MESSAGE_HASH(fm), fma, HASH_BYTES);

	for (int i = 0; i < EXECUTIONS; ++i)  //EXECUTIONS=M
	{
		// generate commitment randomness and r
		memcpy(seedbuf, seeds + i*SEED_BYTES, SEED_BYTES); //seed_i(seedbuf)
		(*ctr)  = EXECUTIONS + i; 
		//P_1_base
		EXPAND(seedbuf, SEED_BUF_BYTES, expand_buf, EXPAND_BUF_LEN);
		// sample r from S2
		sample_S2_with_seed(expand_buf + SEED_BYTES*rings, r[i]); 
		// Memory access at secret location!--->bits_I
		memcpy(commitment_randomness + i*SEED_BYTES , expand_buf + I*SEED_BYTES , SEED_BYTES);
		// compute R_i and commitments
		// compute T_i and commitments
		for (int j = 0; j < rings; ++j)  //base OR, rings=N
		{
			do_action(&R,(public_key*)(pks + j*sizeof(public_key)),r[i]);
			// do_action(&Tprime,(public_key*)(T + j * sizeof(public_key)),r[i]);
			do_action(&Tprime,&T[j],r[i]);
			commit(&R, expand_buf + j * SEED_BYTES, RSIG_SALT(sig), commitments_x + j * HASH_BYTES); //对X_i'承诺：(R_i||expand_buf||sig)--->commitments
			commit(&Tprime, expand_buf + j * SEED_BYTES, RSIG_SALT(sig), commitments_t + j * HASH_BYTES); //对T_i'承诺：(R_i||expand_buf||sig)--->commitments
		
		}
		// generate dummy commitments
		EXPAND(expand_buf + SEED_BYTES * (rings + 1), SEED_BYTES, commitments_x + rings * HASH_BYTES, (rings_round_up - rings) * HASH_BYTES);
		EXPAND(expand_buf + SEED_BYTES * (rings + 1), SEED_BYTES, commitments_t + rings * HASH_BYTES, (rings_round_up - rings) * HASH_BYTES);

		build_tree_and_path(commitments_x, logN, I, FM_ROOTS(fm) + i * HASH_BYTES, paths_x + i * HASH_BYTES * logN);
		build_tree_and_path(commitments_t, logN, I, FM_ROOTS(fm) + (i + EXECUTIONS) * HASH_BYTES, paths_t + i * HASH_BYTES * logN);
	
	}
	// printf("2\n");
	// generate challenge
	EXPAND(fm, FM_BYTES, TRSIG_CHALLENGE(sig), SEED_BYTES);				//----------------------------------TRSIG_CHALLENGE(sig)<--fm[FM_BYTES]
	
	// for(int i=0;i<SEED_BYTES;i++)
	// {
	// 	printf("%x",(TRSIG_CHALLENGE(sig))[i]);
	// }
	// printf("\n");

	unsigned char challenge[EXECUTIONS];
	derive_challenge(TRSIG_CHALLENGE(sig),challenge);

	// printf("3\n");
	//P2_main
	int zeros = 0;
	int ones = 0;
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		if (challenge[i] == 0)
		{
			//P2_base
			// compute and pack z in signature
			add(z, s, r[i]);
			if( !is_in_S3(z) ){
				restarts += 1;
				goto restart;
			}

			#ifdef BG
			XELT W;
			do_action(&W,&X0,z);
			if( !bg_check(&W) ){
				restarts += 1;
				goto restart;
			}
			do_tag_action(&W,&X0,z);
			if( !bg_check(&W) ){
				restarts += 1;
				goto restart;
			}
			#endif

			pack_S3(TRSIG_Z(sig) + zeros*S3_BYTES, z);							//----------------------------------TRSIG_Z(sig)<--z

			// copy commitment randomess to signature
			memcpy(TRSIG_COMMITMENT_RANDOMNESS(sig) + zeros*SEED_BYTES, commitment_randomness + i*SEED_BYTES, SEED_BYTES); 
														//-----------------TRSIG_COMMITMENT_RANDOMNESS(sig)<--commitment_randomness
			// copy Merkle tree path to signature
			memcpy(TRSIG_PATHS(sig) + zeros * logN * HASH_BYTES, paths_x + i * HASH_BYTES * logN, HASH_BYTES * logN);
			memcpy(TRSIG_PATHS(sig) + (zeros + ZEROS) * logN * HASH_BYTES, paths_t + i * HASH_BYTES * logN, HASH_BYTES * logN);
																				//----------------TRSIG_PATHS(sig)<--(paths_x,paths_t)
			zeros++;
		}
	}


	// unpack_S1(TRSIG_B(sig), b);
	release_seeds(seed_tree, EXECUTIONS, challenge, TRSIG_SEEDS(sig,logN) , sig_len );  
	//-----------TRSIG_SEEDS(sig, logN)<--(ci=1对应中间seed集合)																	
	(*sig_len) *= SEED_BYTES;
	(*sig_len) += TRSIG_SEEDS(0,logN);
	printf("sig_len=%ld \n", *(sig_len));


	// printf("4\n");
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		clear_grpelt(r[i]);
	}
	clear_grpelt(z);
	clear_grpelt(s);
	clear_grpelt(a);
	clear_grpelt(b);
	clear_grpelt(c);
	clear_grpelt(d);
	clear_grpelt(k);
}





int  trverify(const unsigned char *pks, const int64_t rings, const unsigned char *L, uint64_t llen, const unsigned char *m, uint64_t mlen, const unsigned char *sig){
	if (rings > (((uint64_t) 1) << 32))
		return -1;

	int valid = 0;

	int logN = log_round_up(rings);
	uint64_t rings_round_up = (((uint64_t)1) << logN);

	//1.T_1,...T_N
	unsigned char fma[HASH_BYTES];
	unsigned char fmc[HASH_BYTES];
	unsigned char fml[HASH_BYTES];
	unsigned char ai[AI_BYTES];
	GRPELTS1L a, b, k;
	public_key T0;
	init_grpelt(a);
	init_grpelt(b);
	init_grpelt(k);

	HASH(L,llen,fml);
	sample_S1L(b,fml);  //b=H_S1(L)
	do_action(&(T0),&X0, b); //T0=H_S1(L)\star S0

#ifdef DEBUG
	printf(" ----(V)T0\n");
	for(int i=0;i<LIMBS;i++)
	{
		printf("%ld ",T0.A.c[i]);
	}
	printf("\n");
#endif
#ifdef DEBUG
		printf(" ----(V)TAG\n");
		for(int j=0;j<LIMBS;j++)
		{
			printf("%ld ",TAG.A.c[j]);
		}
		printf("\n");
#endif

	HASH(m, mlen, fma); 
	sample_S1L(a, fma); //a=H_S1(M)
	pack_S1(ai, a);
	// printf("\n===================v0======================\n");
	unsigned char ID[ID_BYTES]={0};
	public_key T[RINGS];
	for (int64_t i = 0; i < rings; ++i)
	{
		
		conv(ID,i,ID_BYTES);
		memcpy(ai + S1_BYTES, ID, ID_BYTES);
		HASH(ai, AI_BYTES, fmc);
		sample_S1L(k, fmc);			//k=H_S1(a,i)
		do_action(&(T[i]),&TAG, k);
		#ifdef DEBUG
			printf(" ----(V)Ti[%d]\n",i);
			for(int j=0;j<LIMBS;j++)
			{
				printf("%ld ",T[i].A.c[j]);
			}
			printf("\n");
		#endif
	}


	//V_1
	// expand challenge
	unsigned char challenge[EXECUTIONS];
	derive_challenge(TRSIG_CHALLENGE(sig),challenge);  

	// derive seeds
	unsigned char seed_tree[(2*EXECUTIONS-1)*SEED_BYTES];
	unsigned char *seeds = seed_tree + (EXECUTIONS-1)*SEED_BYTES;
	uint64_t nodes_used;
	fill_down(seed_tree,EXECUTIONS, challenge, TRSIG_SEEDS(sig,logN), &nodes_used, TRSIG_SALT(sig));

	unsigned char fm[FM_BYTES];

	// hash message
	HASH(m,mlen,FM_MESSAGE_HASH(fm))

	// copy salt
	memcpy(FM_SALT(fm), TRSIG_SALT(sig), HASH_BYTES);

	// public_key *tag = (public_key *) TRSIG_TAG(sig);
	unsigned char zero_seed[SEED_BYTES] = {0};

	int zeros = 0;
	int ones = 0;
	GRPELTS2 r,z;
	XELT R,Tprime;
	init_grpelt(r);
	init_grpelt(z);

	unsigned char expand_buf[EXPAND_BUF_LEN];
	unsigned char seedbuf[SEED_BUF_BYTES];
	memcpy(seedbuf + SEED_BYTES, TRSIG_SALT(sig) , HASH_BYTES);
	uint32_t *ctr = (uint32_t *) (seedbuf + SEED_BYTES + HASH_BYTES);

	unsigned char commitments_x[HASH_BYTES * rings_round_up];
	unsigned char commitments_t[HASH_BYTES * rings_round_up];
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		if (challenge[i] == 0){
			// unpack z
			unpack_S3(TRSIG_Z(sig) + zeros*S3_BYTES, z);

			if(!is_in_S3(z)){
				printf("z not in S3! \n");
				valid = -1;
				break;
			}

			// compute z * X_0 and z \bullet T_0 
			do_action(&R,&X0,z);
			do_action(&Tprime, &T0, z);
			// commit to it
			commit(&R, TRSIG_COMMITMENT_RANDOMNESS(sig) + SEED_BYTES * zeros, RSIG_SALT(sig), commitments_x);
			commit(&Tprime, TRSIG_COMMITMENT_RANDOMNESS(sig) + SEED_BYTES * zeros, RSIG_SALT(sig), commitments_t);
			// reconstruct root using path
			reconstruct_root(commitments_x, TRSIG_PATHS(sig) + zeros * logN * HASH_BYTES, logN, FM_ROOTS(fm) + i * HASH_BYTES);
			reconstruct_root(commitments_t, TRSIG_PATHS(sig) + (zeros + ZEROS) * logN * HASH_BYTES, logN, FM_ROOTS(fm) + (i + EXECUTIONS) * HASH_BYTES);
			zeros++;
		}
		else
		{
			// generate commitment randomness and r
			memcpy(seedbuf, seeds + i*SEED_BYTES, SEED_BYTES);
			(*ctr)  = EXECUTIONS + i; 
			EXPAND(seedbuf, SEED_BUF_BYTES, expand_buf, EXPAND_BUF_LEN);

			// sample r
			sample_S2_with_seed(expand_buf + SEED_BYTES*rings, r);
			// compute R_i and commitments
			// compute T_i and commitments
			for (int j = 0; j < rings; ++j)
			{
				do_action(&R,(public_key*)(pks + j*sizeof(public_key)),r);
				do_action(&Tprime,&T[j],r);
				commit(&R, expand_buf + j * SEED_BYTES, RSIG_SALT(sig), commitments_x + j * HASH_BYTES);
				commit(&Tprime, expand_buf + j * SEED_BYTES, RSIG_SALT(sig), commitments_t + j * HASH_BYTES);
			}

			// generate dummy commitments
			EXPAND(expand_buf + SEED_BYTES * (rings + 1), SEED_BYTES, commitments_x + rings * HASH_BYTES, (rings_round_up - rings) * HASH_BYTES);
			EXPAND(expand_buf + SEED_BYTES * (rings + 1), SEED_BYTES, commitments_t + rings * HASH_BYTES, (rings_round_up - rings) * HASH_BYTES);
			// compute root
			build_tree_and_path(commitments_x, logN, -1, FM_ROOTS(fm) + i * HASH_BYTES, NULL);
			build_tree_and_path(commitments_t, logN, -1, FM_ROOTS(fm) + (i + EXECUTIONS) * HASH_BYTES, NULL);
			ones++;
		}
	}
	clear_grpelt(r);
	clear_grpelt(z);
	clear_grpelt(a);
	clear_grpelt(b);
	clear_grpelt(k);

	// check hash of first message
	unsigned char challenge_seed[SEED_BYTES];
	EXPAND(fm, FM_BYTES, challenge_seed, SEED_BYTES);
	// for(int i=0;i<SEED_BYTES;i++)
	// {
	// 	printf("%x",challenge_seed[i]);
	// }
	// printf("\n");

	if(memcmp(TRSIG_CHALLENGE(sig) , challenge_seed, SEED_BYTES) != 0){
		printf("challenge seed does not match! \n");
		return -1;
	}

	return valid;
}
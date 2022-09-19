/*****************************************************/
/* SEAL BGV batched Total Covid-19 Deaths calculator */
/* Author: Majdi Maalej                              */
/* Parts of code learned from:                       */
/* 4_bgv_basics.cpp and 2_encoders.cpp               */
/* Total Deaths = sumOf(DeathsInState_i)             */
/*****************************************************/
#include <iostream>
#include <time.h>
#include <stdlib.h>
#include <vector>
#include "seal/seal.h"
#include "examples.h"
#include <sys/resource.h>
#include <unistd.h>

using namespace std;
using namespace seal;

int random_int(int min, int max){
	return min + rand() % (max+1 - min);
}

long get_mem_usage(){
	struct rusage myUsage;
	getrusage(RUSAGE_SELF, &myUsage);
	return myUsage.ru_maxrss;
}

int main(){
	long baseline = get_mem_usage();

	/*****Parameter Generation*****/
	clock_t cc_clock;
	cc_clock = clock();

	EncryptionParameters parms(scheme_type::bgv);
	size_t poly_modulus_degree = 32768;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 55, 46, 46, 46, 46, 60 }));
	parms.set_plain_modulus(65537);

	SEALContext context(parms);
	print_parameters(context);

	/*****Key & Functions Generation*****/
	clock_t key_clock;
	key_clock = clock();

	KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
	keygen.create_public_key(public_key);
	RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

	key_clock = clock() - key_clock;

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	//Set up batch encoder
	BatchEncoder batch_encoder(context);
	size_t slot_count = batch_encoder.slot_count();
	cout<< "slot_count: " << slot_count << endl;
	size_t row_size = slot_count / 2;
	
	cc_clock = clock() - cc_clock - key_clock;
	
	/*****Encoding & Encryption*****/	
	clock_t enc_clock;
	enc_clock = clock();
	
	//Generate the matrices of values 
	int N = 8192;
	vector<uint64_t> BW(slot_count, 0ULL), BY(slot_count, 0ULL), BE(slot_count, 0ULL), BB(slot_count, 0ULL),
									HB(slot_count, 0ULL), HH(slot_count, 0ULL), HE(slot_count, 0ULL), NI(slot_count, 0ULL), 
										MV(slot_count, 0ULL), NW(slot_count, 0ULL), RP(slot_count, 0ULL), SL(slot_count, 0ULL),
											SN(slot_count, 0ULL), ST(slot_count, 0ULL), SH(slot_count, 0ULL), TH(slot_count, 0ULL);
		
	for(int r = 0; r < 2; r++){
		for(int c = 0; c < N/2; c++) {
			BW[r*row_size + c] = random_int(0, 50);
			BY[r*row_size + c] = random_int(0, 50);
			BE[r*row_size + c] = random_int(0, 50);
			BB[r*row_size + c] = random_int(0, 50);
			HB[r*row_size + c] = random_int(0, 50);
			HH[r*row_size + c] = random_int(0, 50);
			HE[r*row_size + c] = random_int(0, 50);
			NI[r*row_size + c] = random_int(0, 50);
			MV[r*row_size + c] = random_int(0, 50);
			NW[r*row_size + c] = random_int(0, 50);
			RP[r*row_size + c] = random_int(0, 50);
			SL[r*row_size + c] = random_int(0, 50);
			SN[r*row_size + c] = random_int(0, 50);
			ST[r*row_size + c] = random_int(0, 50);
			SH[r*row_size + c] = random_int(0, 50);
			TH[r*row_size + c] = random_int(0, 50);
		}
	}
	
	Plaintext plain_BW, plain_BY, plain_BE, plain_BB, plain_HB, plain_HH, plain_HE, plain_NI,
			  plain_MV, plain_NW, plain_RP, plain_SL, plain_SN, plain_ST, plain_SH, plain_TH;

	batch_encoder.encode(BW, plain_BW);
	batch_encoder.encode(BY, plain_BY);
	batch_encoder.encode(BE, plain_BE);
	batch_encoder.encode(BB, plain_BB);
	batch_encoder.encode(HB, plain_HB);
	batch_encoder.encode(HH, plain_HH);
	batch_encoder.encode(HE, plain_HE);
	batch_encoder.encode(NI, plain_NI);
	batch_encoder.encode(MV, plain_MV);
	batch_encoder.encode(NW, plain_NW);
	batch_encoder.encode(RP, plain_RP);
	batch_encoder.encode(SL, plain_SL);
	batch_encoder.encode(SN, plain_SN);
	batch_encoder.encode(ST, plain_ST);
	batch_encoder.encode(SH, plain_SH);
	batch_encoder.encode(TH, plain_TH);

	Ciphertext enc_BW, enc_BY, enc_BE, enc_BB, enc_HB, enc_HH, enc_HE, enc_NI,
			   enc_MV, enc_NW, enc_RP, enc_SL, enc_SN, enc_ST, enc_SH, enc_TH;

	encryptor.encrypt(plain_BW, enc_BW);
	encryptor.encrypt(plain_BY, enc_BY);
	encryptor.encrypt(plain_BE, enc_BE);
	encryptor.encrypt(plain_BB, enc_BB);
	encryptor.encrypt(plain_HB, enc_HB);
	encryptor.encrypt(plain_HH, enc_HH);
	encryptor.encrypt(plain_HE, enc_HE);
	encryptor.encrypt(plain_NI, enc_NI);
	encryptor.encrypt(plain_MV, enc_MV);
	encryptor.encrypt(plain_NW, enc_NW);
	encryptor.encrypt(plain_RP, enc_RP);
	encryptor.encrypt(plain_SL, enc_SL);
	encryptor.encrypt(plain_SN, enc_SN);
	encryptor.encrypt(plain_ST, enc_ST);
	encryptor.encrypt(plain_SH, enc_SH);
	encryptor.encrypt(plain_TH, enc_TH);
	
	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

	Ciphertext enc_TotalDeaths;
	Plaintext plain_one("1");
	
	evaluator.multiply_plain(enc_BW, plain_one, enc_TotalDeaths); // start with TotalDeaths = BW * 1
	evaluator.add_inplace(enc_TotalDeaths, enc_BY);
	evaluator.add_inplace(enc_TotalDeaths, enc_BE);
	evaluator.add_inplace(enc_TotalDeaths, enc_BB);
	evaluator.add_inplace(enc_TotalDeaths, enc_HB);
	evaluator.add_inplace(enc_TotalDeaths, enc_HH);
	evaluator.add_inplace(enc_TotalDeaths, enc_HE);
	evaluator.add_inplace(enc_TotalDeaths, enc_NI);
	evaluator.add_inplace(enc_TotalDeaths, enc_MV);
	evaluator.add_inplace(enc_TotalDeaths, enc_NW);
	evaluator.add_inplace(enc_TotalDeaths, enc_RP);
	evaluator.add_inplace(enc_TotalDeaths, enc_SL);
	evaluator.add_inplace(enc_TotalDeaths, enc_SN);
	evaluator.add_inplace(enc_TotalDeaths, enc_ST);
	evaluator.add_inplace(enc_TotalDeaths, enc_SH);
	evaluator.add_inplace(enc_TotalDeaths, enc_TH);
	
	eval_clock = clock() - eval_clock;

	/*****Decryption & Decoding*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_TotalDeaths;

	decryptor.decrypt(enc_TotalDeaths, plain_TotalDeaths);
	
	vector<uint64_t> totalDeaths;
	batch_encoder.decode(plain_TotalDeaths, totalDeaths);
	
	dec_clock = clock() - dec_clock;
	
	/*****Print*****/
	cout << "Starting the total Covid-19 Deaths calculator with " << N << " instances. "<< endl << endl;

	cout << "Baden-Wuerttemberg: " << endl;
	print_matrix(BW, row_size);

	cout << "Bavaria: " << endl;
	print_matrix(BY, row_size);

	cout << "Berlin: " << endl;
	print_matrix(BE, row_size);
	
	cout << "Brandenburg: " << endl;
	print_matrix(BB, row_size);

	cout << "Bremen: " << endl;
	print_matrix(HB, row_size);
	
	cout << "Hamburg: " << endl;
	print_matrix(HH, row_size);
	
	cout << "Hesse: " << endl;
	print_matrix(HE, row_size);
	
	cout << "Lower Saxony: " << endl;
	print_matrix(NI, row_size);
	
	cout << "Mecklenburg-Vorpommern: " << endl;
	print_matrix(MV, row_size);
	
	cout << "North Rhine-Westphalia: " << endl;
	print_matrix(NW, row_size);
	
	cout << "Rhineland-Palatinate: " << endl;
	print_matrix(RP, row_size);
	
	cout << "Saarland: " << endl;
	print_matrix(SL, row_size);

	cout << "Saxony: " << endl;
	print_matrix(SN, row_size);
	
	cout << "Saxony-Anhalt: " << endl;
	print_matrix(ST, row_size);
	
	cout << "Schleswig-Holstein: " << endl;
	print_matrix(SH, row_size);
	
	cout << "Thuringia: " << endl;
	print_matrix(TH, row_size);
	
	cout << "Total Covid-19 Deaths: " << endl;
	print_matrix(totalDeaths, row_size);

	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
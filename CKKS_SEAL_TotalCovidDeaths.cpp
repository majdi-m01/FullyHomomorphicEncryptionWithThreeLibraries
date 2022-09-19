/**********************************************/
/* SEAL CKKS Total Covid-19 Deaths calculator */
/* Author: Majdi Maalej                       */
/* Parts of code learned from:                */
/* 4_CKKS_basics.cpp                          */
/* Total Deaths = sumOf(DeathsInState_i)      */
/**********************************************/
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

	EncryptionParameters parms(scheme_type::ckks);
	size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 55, 46, 46, 46, 46, 60 }));
	double scale = pow(2.0, 40);

	SEALContext context(parms);
	print_parameters(context);

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

    KeyGenerator keygen(context);
	PublicKey public_key;
	keygen.create_public_key(public_key);
	RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    auto secret_key = keygen.secret_key();
	
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
	
	cc_clock = clock() - cc_clock - key_clock;

	/*****Encoding and Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

    int N = 8192; 
	vector<double> BW, BY, BE, BB, HB, HH, HE, NI,
				 MV, NW, RP, SL, SN, ST, SH, TH;   

	for(int i = 0; i < N; i++){
		BW.push_back(round(random_int(0, 50)));
		BY.push_back(round(random_int(0, 50)));
		BE.push_back(round(random_int(0, 50)));
		BB.push_back(round(random_int(0, 50)));
		HB.push_back(round(random_int(0, 50)));
		HH.push_back(round(random_int(0, 50)));
		HE.push_back(round(random_int(0, 50)));
		NI.push_back(round(random_int(0, 50)));
		MV.push_back(round(random_int(0, 50)));
		NW.push_back(round(random_int(0, 50)));
		RP.push_back(round(random_int(0, 50)));
		SL.push_back(round(random_int(0, 50)));
		SN.push_back(round(random_int(0, 50)));
		ST.push_back(round(random_int(0, 50)));
		SH.push_back(round(random_int(0, 50)));
		TH.push_back(round(random_int(0, 50)));
	}

    Plaintext plain_BW, plain_BY, plain_BE, plain_BB, plain_HB, plain_HH, plain_HE, plain_NI,
			  plain_MV, plain_NW, plain_RP, plain_SL, plain_SN, plain_ST, plain_SH, plain_TH;

    encoder.encode(BW, scale, plain_BW);
    encoder.encode(BY, scale, plain_BY);
    encoder.encode(BE, scale, plain_BE);
	encoder.encode(BB, scale, plain_BB);
	encoder.encode(HB, scale, plain_HB);
	encoder.encode(HH, scale, plain_HH);
	encoder.encode(HE, scale, plain_HE);
	encoder.encode(NI, scale, plain_NI);
	encoder.encode(MV, scale, plain_MV);
	encoder.encode(NW, scale, plain_NW);
	encoder.encode(RP, scale, plain_RP);
	encoder.encode(SL, scale, plain_SL);
	encoder.encode(SN, scale, plain_SN);
	encoder.encode(ST, scale, plain_ST);
	encoder.encode(SH, scale, plain_SH);
	encoder.encode(TH, scale, plain_TH);

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

	evaluator.add(enc_BW, enc_BY, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_BE, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_BB, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_HB, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_HH, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_HE, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_NI, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_MV, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_NW, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_RP, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_SL, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_SN, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_ST, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_SH, enc_TotalDeaths);
	evaluator.add(enc_TotalDeaths, enc_TH, enc_TotalDeaths);

	eval_clock = clock() - eval_clock;

	/*****Decryption & Decoding*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_TotalDeaths;
	decryptor.decrypt(enc_TotalDeaths, plain_TotalDeaths);
	
	vector<double> totalDeaths;
	encoder.decode(plain_TotalDeaths, totalDeaths);

	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "Starting the total Covid-19 Deaths calculator with " << N << " instances. "<< endl << endl;

	cout << "Baden-Wuerttemberg: " << endl;
	print_vector(BW, 10, 4);

	cout << "Bavaria: " << endl;
	print_vector(BY, 10, 4);

	cout << "Berlin: " << endl;
	print_vector(BE, 10, 4);
	
	cout << "Brandenburg: " << endl;
	print_vector(BB, 10, 4);

	cout << "Bremen: " << endl;
	print_vector(HB, 10, 4);
	
	cout << "Hamburg: " << endl;
	print_vector(HH, 10, 4);
	
	cout << "Hesse: " << endl;
	print_vector(HE, 10, 4);
	
	cout << "Lower Saxony: " << endl;
	print_vector(NI, 10, 4);
	
	cout << "Mecklenburg-Vorpommern: " << endl;
	print_vector(MV, 10, 4);
	
	cout << "North Rhine-Westphalia: " << endl;
	print_vector(NW, 10, 4);
	
	cout << "Rhineland-Palatinate: " << endl;
	print_vector(RP, 10, 4);
	
	cout << "Saarland: " << endl;
	print_vector(SL, 10, 4);

	cout << "Saxony: " << endl;
	print_vector(SN, 10, 4);
	
	cout << "Saxony-Anhalt: " << endl;
	print_vector(ST, 10, 4);
	
	cout << "Schleswig-Holstein: " << endl;
	print_vector(SH, 10, 4);
	
	cout << "Thuringia: " << endl;
	print_vector(TH, 10, 4);
	
	cout << "Total Covid-19 Deaths: " << endl;
	print_vector(totalDeaths, 10, 4);
	
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;
	
	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
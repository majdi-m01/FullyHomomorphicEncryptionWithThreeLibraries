/********************************************/
/* SEAL BGV batched Luminousity calculator  */
/* Author: Majdi Maalej                     */
/* Parts of code learned from:              */
/* 4_bgv_basics.cpp and 2_encoders.cpp      */
/* Luminousity/(4*pi*sigma) = (r^2) * (T^4) */
/********************************************/
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
	parms.set_plain_modulus(2147352577);

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
	size_t row_size = slot_count / 2;
	
	cc_clock = clock() - cc_clock - key_clock;
	
	/*****Encoding & Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();
	
	//Generate the matrices of values 
	int N = 8192;
	vector<uint64_t> Radius(slot_count, 0ULL);    
	vector<uint64_t> SurfaceTemperature(slot_count, 0ULL);                	

	for(int r = 0; r < 2; r++){
		for(int c = 0; c < N/2; c++) {
			Radius[r*row_size + c] = random_int(9, 95);
			SurfaceTemperature[r*row_size + c] = random_int(2, 22);
		}
	}
	
	Plaintext plain_radius;
	Plaintext plain_temperature;

	batch_encoder.encode(Radius, plain_radius);
	batch_encoder.encode(SurfaceTemperature, plain_temperature);

	Ciphertext enc_radius;
	Ciphertext enc_temperature;

	encryptor.encrypt(plain_radius, enc_radius);
	encryptor.encrypt(plain_temperature, enc_temperature);

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();
	
	Ciphertext enc_radiusSquared, enc_temperatureSquared1, enc_temperatureSquared2, enc_temperatureQuadruple;
	Ciphertext enc_Result;
	
	evaluator.square(enc_temperature, enc_temperatureSquared1);
	evaluator.relinearize_inplace(enc_temperatureSquared1, relin_keys);
	evaluator.mod_switch_to_next_inplace(enc_temperatureSquared1);
	
	evaluator.square(enc_temperature, enc_temperatureSquared2);
	evaluator.relinearize_inplace(enc_temperatureSquared2, relin_keys);
	evaluator.mod_switch_to_next_inplace(enc_temperatureSquared2);
	
	evaluator.square(enc_radius, enc_radiusSquared);
	evaluator.relinearize_inplace(enc_radiusSquared, relin_keys);
	evaluator.mod_switch_to_next_inplace(enc_radiusSquared);
	
	evaluator.multiply(enc_temperatureSquared1, enc_temperatureSquared2, enc_temperatureQuadruple);
	evaluator.relinearize_inplace(enc_temperatureQuadruple, relin_keys);
	
	evaluator.multiply(enc_radiusSquared, enc_temperatureQuadruple, enc_Result);
	evaluator.relinearize_inplace(enc_Result, relin_keys);
	
	eval_clock = clock() - eval_clock;

	/*****Decryption & Decoding*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_Result;

	decryptor.decrypt(enc_Result, plain_Result);
	
	vector<uint64_t> result;
	batch_encoder.decode(plain_Result, result);
	
	dec_clock = clock() - dec_clock;
	
	/*****Print*****/
	cout << "Starting the ( Luminousity/(4*pi*sigma) ) of a star caluculator with " << N << " instances. "<< endl << endl;

	cout << "Radius: " << endl;
	print_matrix(Radius, row_size);

	cout << "Surface Temperature: " << endl;
	print_matrix(SurfaceTemperature, row_size);

	cout << "Result ( Luminousity/(4*pi*sigma) ): " << endl;
	print_matrix(result, row_size);
	
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
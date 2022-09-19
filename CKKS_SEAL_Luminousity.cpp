/********************************************/
/* SEAL CKKS Luminousity calculator         */
/* Author: Majdi Maalej                     */
/* Parts of code learned from:              */
/* 4_CKKS_basics.cpp                        */
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

double random_double(double  min, double  max){
	double f = (double)rand() / RAND_MAX;
    return min + f * (max - min);
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
	vector<double> Radius; 
	vector<double> SurfaceTemperature;    

	for(int i = 0; i < N; i++){
		Radius.push_back(random_double(9, 81));
		SurfaceTemperature.push_back(random_double(2, 20));
	}
	
    Plaintext plain_radius, plain_temperature;
	
    encoder.encode(Radius, scale, plain_radius);
    encoder.encode(SurfaceTemperature, scale, plain_temperature);

    Ciphertext enc_radius, enc_temperature;
	
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
	evaluator.rescale_to_next_inplace(enc_temperatureSquared1);
	
	evaluator.square(enc_temperature, enc_temperatureSquared2);
	evaluator.relinearize_inplace(enc_temperatureSquared2, relin_keys);
	evaluator.rescale_to_next_inplace(enc_temperatureSquared2);
	
	evaluator.square(enc_radius, enc_radiusSquared);
	evaluator.relinearize_inplace(enc_radiusSquared, relin_keys);
	evaluator.rescale_to_next_inplace(enc_radiusSquared);
	
	parms_id_type last_parms_id = enc_radiusSquared.parms_id();
	evaluator.mod_switch_to_inplace(enc_temperatureSquared1, last_parms_id);
	evaluator.mod_switch_to_inplace(enc_temperatureSquared2, last_parms_id);
	
	evaluator.multiply(enc_temperatureSquared1, enc_temperatureSquared2, enc_temperatureQuadruple);
	evaluator.relinearize_inplace(enc_temperatureQuadruple, relin_keys);
	
	evaluator.mod_switch_to_inplace(enc_temperatureQuadruple, last_parms_id);
	
	evaluator.multiply(enc_radiusSquared, enc_temperatureQuadruple, enc_Result);
	evaluator.relinearize_inplace(enc_Result, relin_keys);

	eval_clock = clock() - eval_clock;

	/*****Decryption & Decoding*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_Result;
	decryptor.decrypt(enc_Result, plain_Result);
	
	vector<double> result;
	encoder.decode(plain_Result, result);

	dec_clock = clock() - dec_clock;
	
	//Luminousity calculator
	/*vector<long double> Luminousity = (vector<long double>)Result;
	const double boltzmann_constant = 1.3806503e-23;
	const double pi = atan(1)*4;
	const double myConstant = 4*boltzmann_constant*pi;
	for(int i=0; i < Luminousity.size(); ++i){
		Luminousity[i] *= myConstant;
	}*/

	/*****Print*****/
	cout << "Starting the ( Luminousity/(4*pi*sigma) ) of a star caluculator with " << N << " instances. "<< endl << endl;

	cout << "Radius: " << endl;
	print_vector(Radius, 10, 4);

	cout << "Surface Temperature: " << endl;
	print_vector(SurfaceTemperature, 10, 4);

	cout << "Result ( Luminousity/(4*pi*sigma) ): " << endl;
	print_vector(result, 10, 4);
	
	//cout << "Luminousity: " << endl;
	//print_vector(Luminousity, 10, 4);
	
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
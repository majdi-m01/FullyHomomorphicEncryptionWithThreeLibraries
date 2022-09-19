/********************************************/
/* PALISADE BGV Luminousity calculator      */
/* Author: Majdi Maalej                     */
/* Parts of code learned from:              */
/* demo-packing.cpp                         */
/* Luminousity/(4*pi*sigma) = (r^2) * (T^4) */
/********************************************/
#include "palisade.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <fstream>
#include <random>
#include <iterator>
#include <sys/resource.h>
#include <unistd.h>

using namespace std;
using namespace lbcrypto;

int64_t random_int(int64_t min, int64_t max){
	return min + rand() % (max+1 - min);
}

void print(Plaintext v, int length){
    int print_size = 20;
    int end_size = 2;

    cout << endl;
    cout << "    [";

    for (int i = 0; i < print_size; i++){
        cout << setw(3) << right << v->GetPackedValue()[i] << ",";
    }
	
    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++){
        cout << setw(3) << v->GetPackedValue()[i] << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
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
	
	 // Set the main parameters
	uint32_t depth = 3;
	int plaintextModulus = 2147352577;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	usint ringDim = 32768;
	uint32_t numLargeDigits = 6;
	usint firstModSize = 55;
	usint dcrtBits = 60;
	int batchSize = 8192;
	

	// Instantiate the crypto context
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
																						depth, 
																						plaintextModulus, 
																						securityLevel, 
																						sigma, 
																						depth, 
																						OPTIMIZED, 
																						BV,
																						ringDim,
																						numLargeDigits,
																						firstModSize,
																						dcrtBits,
																						0, //relinWindow
																						batchSize,
																						AUTO);
																						
	cout << "cyclotomic degree: " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() /2 <<endl<<endl;

	//Enable wanted functions
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	cc_clock = clock() - cc_clock;

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

	LPKeyPair<DCRTPoly> kp = cc->KeyGen();
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);
	long N = 8192;

	key_clock = clock() - key_clock;

	/*****Encoding and Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();
	
	vector<int64_t> Radius;
	vector<int64_t> SurfaceTemperature;
	
	for(int i = 0; i < N; i++){
		Radius.push_back(random_int(9, 81));
		SurfaceTemperature.push_back(random_int(2, 20));
	}
	
	Plaintext plain_radius = cc->MakePackedPlaintext(Radius);
	Plaintext plain_temperature = cc->MakePackedPlaintext(SurfaceTemperature);

	//Encrypt the encodings
	auto enc_radius = cc->Encrypt(kp.publicKey, plain_radius);
	auto enc_temperature = cc->Encrypt(kp.publicKey, plain_temperature);
	
	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();
	
	vector<Ciphertext<DCRTPoly>> ciphertexts;
	
	ciphertexts.push_back(enc_radius);
	ciphertexts.push_back(enc_radius);
	ciphertexts.push_back(enc_temperature);
	ciphertexts.push_back(enc_temperature);
	ciphertexts.push_back(enc_temperature);
	ciphertexts.push_back(enc_temperature);
	
	auto enc_Result = cc->EvalMultMany(ciphertexts);

	eval_clock = clock() - eval_clock;
	
	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_Result;

	cc->Decrypt(kp.secretKey, enc_Result, &plain_Result);
	
	dec_clock = clock() - dec_clock;
	
	/*
	//Luminousity calculator
	vector<long double> Luminousity = (vector<long double>)Result;
	const double boltzmann_constant = 1.3806503e-23;
	const double pi = atan(1)*4;
	const double myConstant = 4*boltzmann_constant*pi;
	for(int i=0; i < Luminousity.size(); ++i){
		Luminousity[i] *= myConstant;
	}
	*/

	/*****Print*****/
	cout << "Radius \n\t" << endl;
	print(plain_radius, N);
	
	cout << "SurfaceTemperature \n\t" << endl;	
	print(plain_temperature, N);
	
	cout << "Result ( Luminousity/(4*pi*sigma) )\n\t"  << endl;
	print(plain_Result, N);
	
	//cout << "Luminousity: " << endl;
	//printDouble(Luminousity, num_slots);
	
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
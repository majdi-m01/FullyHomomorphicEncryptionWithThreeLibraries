/********************************************/
/* PALISADE CKKS Luminousity calculator     */
/* Author: Alycia N. Carey                  */
/* Parts of code learned from:              */
/* demo-simple-real-numbers.cpp             */
/* Luminousity/(4*pi*sigma) = (r^2) * (T^4) */
/********************************************/
#include "palisade.h"
#include "ciphertext-ser.h"                                                                                                            
#include "cryptocontext-ser.h"                                                                                                         
#include "pubkeylp-ser.h"                                                                                                              
#include "scheme/ckks/ckks-ser.h"                                                                                                      
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

using namespace std;
using namespace lbcrypto;

void print(Plaintext v, int length){
    int print_size = 20;
    int end_size = 2;

    cout << endl;
    cout << "    [";

    for (int i = 0; i < print_size; i++){
        cout << setw(3) << right << v->GetCKKSPackedValue()[i].real() << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++){
        cout << setw(3) << v->GetCKKSPackedValue()[i].real() << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
}

void printDouble(vector<long double> v, long length){
	int print_size = 20;
    int end_size = 2;
	
    cout << endl;
    cout << "    [";
	
    for (int i = 0; i < print_size; i++){
        cout << setw(3) << right << v[i] << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++){
        cout << setw(3) << v[i] << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
}

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

	uint32_t multiplicativeDepth = 6;
	uint32_t maxDepth = 3;
	uint32_t scaleFactorBits = 40;
	uint32_t batchSize = 8192;
	SecurityLevel securityLevel = HEStd_128_classic;
	usint ringDim = 32768;
	uint32_t numLargeDigits = 6;
	usint firstModSize = 55;

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
																					  multiplicativeDepth,
																					  scaleFactorBits,
																					  batchSize,
																					  securityLevel,
																					  ringDim,
																					  APPROXRESCALE,
																					  BV,
																					  numLargeDigits,
																					  maxDepth,
																					  firstModSize,
																					  0, //relinWindows
																					  OPTIMIZED);

	cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << endl << endl;

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	cc_clock = clock() - cc_clock;

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

	auto keys = cc->KeyGen();
	cc->EvalMultKeyGen(keys.secretKey);
	cc->EvalAtIndexKeyGen(keys.secretKey, { 1, -2 });

	key_clock = clock() - key_clock;

	/*****Encoding & Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	int N = 8192; 
	vector<complex<double>> Radius; 
	vector<complex<double>> SurfaceTemperature; 

	for(int i = 0; i < N; i++){
		Radius.push_back(random_double(9, 81));
		SurfaceTemperature.push_back(random_double(2, 20));
	}

	Plaintext plain_radius = cc->MakeCKKSPackedPlaintext(Radius);
	Plaintext plain_temperature = cc->MakeCKKSPackedPlaintext(SurfaceTemperature);

	// Encrypt the encoded vectors
	auto enc_radius = cc->Encrypt(keys.publicKey, plain_radius);
	auto enc_temperature = cc->Encrypt(keys.publicKey, plain_temperature);

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
	cout.precision(6);

	cc->Decrypt(keys.secretKey, enc_Result, &plain_Result);

	dec_clock = clock() - dec_clock;
	
	/*
	//Luminousity calculator
	vector<long double> Luminousity = Result;
	const double boltzmann_constant = 1.3806503e-23;
	const double pi = atan(1)*4;
	const double myConstant = 4*boltzmann_constant*pi;
	for(int i=0; i < Luminousity.size(); ++i){
		Luminousity[i] *= myConstant;
	}
	*/

	/*****Print*****/
	cout << "Starting the ( Luminousity/(4*pi*sigma) ) of a star caluculator with " << N << " instances. "<< endl << endl;

	cout << "Radius: " << endl;
	print(plain_radius, N);

	cout << "Surface Temperature: " << endl;
	print(plain_temperature, N);

	cout << "Result: " << endl;
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
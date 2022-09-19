/********************************************/
/* PALISADE BFVrns Luminousity calculator   */
/* Author: Majdi Maalej                     */
/* Parts of code learned from:              */
/* demo-simple-exmple.cpp                   */
/* Luminousity/(4*pi*sigma) = (r^2) * (T^4) */
/********************************************/
#include "palisade.h"
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
        cout << setw(3) << right << v->GetPackedValue()[i] << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++){
        cout << setw(3) << v->GetPackedValue()[i] << ((i != length - 1) ? "," : " ]\n");
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
	srand(time(NULL));

	/*****Parameter Generation*****/
	clock_t cc_clock;
	cc_clock = clock();
	
	//Parameter Selection
	int plaintextModulus = 2147352577;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	int numMults = 3;
	uint32_t depth = 3;
	usint dcrtBits = 60;
	usint ringDim = 32768;

	//Create the cryptoContext with the desired parameters
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
																						plaintextModulus, 
																						securityLevel, 
																					    sigma, 
																						0, //numAdds
																						numMults,
																						0, //numKeyswitches
																						OPTIMIZED,
																						depth,
																						0, //relinWindows
																						dcrtBits,
																						ringDim);
	cout << "cyclotomic degree: " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() /2 <<endl<<endl;
	//Enable wanted functions
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	cc_clock = clock() - cc_clock;

	/*****Key Generation*****/ 
	clock_t key_clock;
	key_clock = clock();

	//Create the container for the public key   
	LPKeyPair<DCRTPoly> keyPair;

	//Generate the keyPair
	keyPair = cc->KeyGen();

	//Generate the relinearization key
	cc->EvalMultKeyGen(keyPair.secretKey);

	key_clock = clock() - key_clock;

	/*****Encoding & Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	//Create and encode the plaintext vectors and variables
	int N = 8192; 
	vector<long> Radius;
	vector<long> SurfaceTemperature;

	for(int i = 0; i < N; i++){
		Radius.push_back(random_int(9, 81));
		SurfaceTemperature.push_back(random_int(2, 20));
	}

	Plaintext plain_radius = cc->MakePackedPlaintext(Radius);
	Plaintext plain_temperature = cc->MakePackedPlaintext(SurfaceTemperature);

	//Encrypt the encodings
	auto enc_radius = cc->Encrypt(keyPair.publicKey, plain_radius);
	auto enc_temperature = cc->Encrypt(keyPair.publicKey, plain_temperature);

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
	cc->Decrypt(keyPair.secretKey, enc_Result, &plain_Result);

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

	cout << "Result ( Luminousity/(4*pi*sigma) ): " << endl;
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
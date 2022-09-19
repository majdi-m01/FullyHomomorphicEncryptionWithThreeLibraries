/****************************************************/
/* PALISADE BFVrns Total Covid-19 Deaths calculator */
/* Author: Majdi Maalej                             */
/* Parts of code learned from:                      */
/* demo-simple-exmple.cpp                           */
/* Total Deaths = sumOf(DeathsInState_i)            */
/****************************************************/
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
	int plaintextModulus = 65537;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	int numAdds = 15;
	uint32_t depth = 3;
	usint dcrtBits = 60;
	usint ringDim = 32768;

	//Create the cryptoContext with the desired parameters
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
																						plaintextModulus, 
																						securityLevel, 
																					    sigma, 
																						numAdds,
																						0, //numMults
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

	/*****Generate Keys*****/ 
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
	vector<long> BW, BY, BE, BB, HB, HH, HE, NI, 
				 MV, NW, RP, SL, SN, ST, SH, TH;

	for(int i = 0; i < N; i++){
		BW.push_back(random_int(0, 50));
		BY.push_back(random_int(0, 50));
		BE.push_back(random_int(0, 50));
		BB.push_back(random_int(0, 50));
		HB.push_back(random_int(0, 50));
		HH.push_back(random_int(0, 50));
		HE.push_back(random_int(0, 50));
		NI.push_back(random_int(0, 50));
		MV.push_back(random_int(0, 50));
		NW.push_back(random_int(0, 50));
		RP.push_back(random_int(0, 50));
		SL.push_back(random_int(0, 50));
		SN.push_back(random_int(0, 50));
		ST.push_back(random_int(0, 50));
		SH.push_back(random_int(0, 50));
		TH.push_back(random_int(0, 50));
	}

	Plaintext plain_BW = cc->MakePackedPlaintext(BW);
	Plaintext plain_BY = cc->MakePackedPlaintext(BY);
	Plaintext plain_BE = cc->MakePackedPlaintext(BE);
	Plaintext plain_BB = cc->MakePackedPlaintext(BB);
	Plaintext plain_HB = cc->MakePackedPlaintext(HB);
	Plaintext plain_HH = cc->MakePackedPlaintext(HH);
	Plaintext plain_HE = cc->MakePackedPlaintext(HE);
	Plaintext plain_NI = cc->MakePackedPlaintext(NI);
	Plaintext plain_MV = cc->MakePackedPlaintext(MV);
	Plaintext plain_NW = cc->MakePackedPlaintext(NW);
	Plaintext plain_RP = cc->MakePackedPlaintext(RP);
	Plaintext plain_SL = cc->MakePackedPlaintext(SL);
	Plaintext plain_SN = cc->MakePackedPlaintext(SN);
	Plaintext plain_ST = cc->MakePackedPlaintext(ST);
	Plaintext plain_SH = cc->MakePackedPlaintext(SH);
	Plaintext plain_TH = cc->MakePackedPlaintext(TH);

	//Encrypt the encodings
	auto enc_BW = cc->Encrypt(keyPair.publicKey, plain_BW);
	auto enc_BY = cc->Encrypt(keyPair.publicKey, plain_BY);
	auto enc_BE = cc->Encrypt(keyPair.publicKey, plain_BE);
	auto enc_BB = cc->Encrypt(keyPair.publicKey, plain_BB);
	auto enc_HB = cc->Encrypt(keyPair.publicKey, plain_HB);
	auto enc_HH = cc->Encrypt(keyPair.publicKey, plain_HH);
	auto enc_HE = cc->Encrypt(keyPair.publicKey, plain_HE);
	auto enc_NI = cc->Encrypt(keyPair.publicKey, plain_NI);
	auto enc_MV = cc->Encrypt(keyPair.publicKey, plain_MV);
	auto enc_NW = cc->Encrypt(keyPair.publicKey, plain_NW);
	auto enc_RP = cc->Encrypt(keyPair.publicKey, plain_RP);
	auto enc_SL = cc->Encrypt(keyPair.publicKey, plain_SL);
	auto enc_SN = cc->Encrypt(keyPair.publicKey, plain_SN);
	auto enc_ST = cc->Encrypt(keyPair.publicKey, plain_ST);
	auto enc_SH = cc->Encrypt(keyPair.publicKey, plain_SH);
	auto enc_TH = cc->Encrypt(keyPair.publicKey, plain_TH);
	
	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

	auto enc_TotalDeaths = cc->EvalAdd(enc_BW, enc_BY);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_BE);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_BB);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_HB);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_HH);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_HE);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_NI);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_MV);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_NW);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_RP);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_SL);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_SN);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_ST);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_SH);
	enc_TotalDeaths = cc->EvalAdd(enc_TotalDeaths, enc_TH);

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_TotalDeaths;
	cc->Decrypt(keyPair.secretKey, enc_TotalDeaths, &plain_TotalDeaths);

	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "Starting the total Covid-19 Deaths calculator with " << N << " instances. "<< endl << endl;

	cout << "Baden-Wuerttemberg: " << endl;
	print(plain_BW, N);

	cout << "Bavaria: " << endl;
	print(plain_BY, N);

	cout << "Berlin: " << endl;
	print(plain_BE, N);
	
	cout << "Brandenburg: " << endl;
	print(plain_BB, N);

	cout << "Bremen: " << endl;
	print(plain_HB, N);
	
	cout << "Hamburg: " << endl;
	print(plain_HH, N);
	
	cout << "Hesse: " << endl;
	print(plain_HE, N);
	
	cout << "Lower Saxony: " << endl;
	print(plain_NI, N);
	
	cout << "Mecklenburg-Vorpommern: " << endl;
	print(plain_MV, N);
	
	cout << "North Rhine-Westphalia: " << endl;
	print(plain_NW, N);
	
	cout << "Rhineland-Palatinate: " << endl;
	print(plain_RP, N);
	
	cout << "Saarland: " << endl;
	print(plain_SL, N);

	cout << "Saxony: " << endl;
	print(plain_SN, N);
	
	cout << "Saxony-Anhalt: " << endl;
	print(plain_ST, N);
	
	cout << "Schleswig-Holstein: " << endl;
	print(plain_SH, N);
	
	cout << "Thuringia: " << endl;
	print(plain_TH, N);
	
	cout << "Total Covid-19 Deaths: " << endl;
	print(plain_TotalDeaths, N);
	
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
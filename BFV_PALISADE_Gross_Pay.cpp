/****************************************************************/
/* PALISADE BFVrns Gross Pay calculator                         */
/* Author: Majdi Maalej                                         */
/* Parts of code learned from:                                  */
/* demo-simple-exmple.cpp                                       */
/* GrossPay = (NumberofRegularHours * RegularHourlyRate)        */
/*                +(NumberofOvertimeHours * OvertimeHourlyRate) */
/****************************************************************/
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
	vector<long> NumberOfRegularHours;
	vector<long> RegularHourlyRate;
	vector<long> NumberOfOvertimeHours;
	vector<long> OvertimeHourlyRate; 

	for(int i = 0; i < N; i++){
		NumberOfRegularHours.push_back(random_int(40, 192));
		RegularHourlyRate.push_back(random_int(9, 30));
		NumberOfOvertimeHours.push_back(random_int(0, 40));
		OvertimeHourlyRate.push_back(random_int(9, 20));
	}

	Plaintext plain_regular_hours = cc->MakePackedPlaintext(NumberOfRegularHours);
	Plaintext plain_regular_rate = cc->MakePackedPlaintext(RegularHourlyRate);
	Plaintext plain_overtime_hours = cc->MakePackedPlaintext(NumberOfOvertimeHours);
	Plaintext plain_overtime_rate = cc->MakePackedPlaintext(OvertimeHourlyRate);

	//Encrypt the encodings
	auto enc_regular_hours = cc->Encrypt(keyPair.publicKey, plain_regular_hours);
	auto enc_regular_rate = cc->Encrypt(keyPair.publicKey, plain_regular_rate);
	auto enc_overtime_hours = cc->Encrypt(keyPair.publicKey, plain_overtime_hours);
	auto enc_overtime_rate = cc->Encrypt(keyPair.publicKey, plain_overtime_rate);

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

	auto enc_StandardPay = cc->EvalMult(enc_regular_hours, enc_regular_rate);
	auto enc_GrossPay = cc->EvalMult(enc_overtime_hours, enc_overtime_rate);
	enc_GrossPay = cc->EvalAdd(enc_GrossPay, enc_StandardPay);

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_GrossPay;
	cc->Decrypt(keyPair.secretKey, enc_GrossPay, &plain_GrossPay);

	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "Starting the Gross Pay calculator with " << N << " instances. "<< endl << endl;

	cout << "NumberOfRegularHours: " << endl;
	print(plain_regular_hours, N);

	cout << "RegularHourlyRate: " << endl;
	print(plain_regular_rate, N);

	cout << "NumberOfOvertimeHours: " << endl;
	print(plain_overtime_hours, N);
	
	cout << "OvertimeHourlyRate: " << endl;
	print(plain_overtime_rate, N);

	cout << "GrossPay: " << endl;
	print(plain_GrossPay, N);

	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
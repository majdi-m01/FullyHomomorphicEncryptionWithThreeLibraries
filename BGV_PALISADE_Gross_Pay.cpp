/****************************************************************/
/* PALISADE BGV Gross Pay calculator                            */
/* Author: Majdi Maalej                                         */
/* Parts of code learned from:                                  */
/* demo-packing.cpp                                             */
/* GrossPay = (NumberofRegularHours * RegularHourlyRate)        */
/*                +(NumberofOvertimeHours * OvertimeHourlyRate) */
/****************************************************************/
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

int random_int(int min, int max){
	return min + rand() % (max+1 - min);
}

long get_mem_usage(){
	struct rusage myUsage;
	getrusage(RUSAGE_SELF, &myUsage);
	return myUsage.ru_maxrss;
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

int main(){
	long baseline = get_mem_usage();
	
	/*****Parameter Generation*****/
	clock_t cc_clock;
	cc_clock = clock();

    // Set the main parameters
	uint32_t depth = 3;
	int plaintextModulus = 65537;
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

	key_clock = clock() - key_clock;

	/*****Encoding & Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();
	
	vector<long> NumberOfRegularHours;
	vector<long> RegularHourlyRate;
	vector<long> NumberOfOvertimeHours;
	vector<long> OvertimeHourlyRate;
	int N= 8192;
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
	auto enc_regular_hours = cc->Encrypt(kp.publicKey, plain_regular_hours);
	auto enc_regular_rate = cc->Encrypt(kp.publicKey, plain_regular_rate);
	auto enc_overtime_hours = cc->Encrypt(kp.publicKey, plain_overtime_hours);
	auto enc_overtime_rate = cc->Encrypt(kp.publicKey, plain_overtime_rate);

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

	cc->Decrypt(kp.secretKey, enc_GrossPay, &plain_GrossPay);
	
	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "NumberOfRegularHours \n\t" << endl;
	print(plain_regular_hours, N);
	cout << "RegularHourlyRate \n\t" << endl;
	print(plain_regular_rate, N);
	cout << "NumberOfOvertimeHours \n\t" << endl;
	print(plain_overtime_hours, N);
	cout << "OvertimeHourlyRate \n\t" << endl;
	print(plain_overtime_rate, N);
	
	cout << "Grosspay \n\t" << endl;
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
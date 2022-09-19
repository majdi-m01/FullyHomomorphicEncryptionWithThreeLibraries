/****************************************************************/
/* PALISADE CKKS Gross Pay calculator                           */
/* Author: Majdi Maalej                                         */
/* Parts of code learned from:                                  */
/* demo-simple-real-numbers.cpp                                 */
/* GrossPay = (NumberofRegularHours * RegularHourlyRate)        */
/*                +(NumberofOvertimeHours * OvertimeHourlyRate) */
/****************************************************************/
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

	uint32_t depth = 3;
	uint32_t scaleFactorBits = 40;
	uint32_t batchSize = 8192;
	SecurityLevel securityLevel = HEStd_128_classic;
	usint ringDim = 32768;
	uint32_t numLargeDigits = 6;
	usint firstModSize = 55;

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
																					  depth,
																					  scaleFactorBits,
																					  batchSize,
																					  securityLevel,
																					  ringDim,
																					  APPROXRESCALE,
																					  BV,
																					  numLargeDigits,
																					  depth,
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
	vector<complex<double>> NumberOfRegularHours;
	vector<complex<double>> RegularHourlyRate;
	vector<complex<double>> NumberOfOvertimeHours;
	vector<complex<double>> OvertimeHourlyRate;

	for(int i = 0; i < N; i++){
		NumberOfRegularHours.push_back(random_double(40,192));
		RegularHourlyRate.push_back(random_double(9,30));
		NumberOfOvertimeHours.push_back(random_double(0,40));
		OvertimeHourlyRate.push_back(random_double(9,20));
	}
	
	Plaintext plain_regular_hours = cc->MakeCKKSPackedPlaintext(NumberOfRegularHours);
	Plaintext plain_regular_rate = cc->MakeCKKSPackedPlaintext(RegularHourlyRate);
	Plaintext plain_overtime_hours = cc->MakeCKKSPackedPlaintext(NumberOfOvertimeHours);
	Plaintext plain_overtime_rate = cc->MakeCKKSPackedPlaintext(OvertimeHourlyRate);

	// Encrypt the encoded vectors
	auto enc_regular_hours = cc->Encrypt(keys.publicKey, plain_regular_hours);
	auto enc_regular_rate = cc->Encrypt(keys.publicKey, plain_regular_rate);
	auto enc_overtime_hours = cc->Encrypt(keys.publicKey, plain_overtime_hours);
	auto enc_overtime_rate = cc->Encrypt(keys.publicKey, plain_overtime_rate);

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
	cout.precision(6);

	cc->Decrypt(keys.secretKey, enc_GrossPay, &plain_GrossPay);

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
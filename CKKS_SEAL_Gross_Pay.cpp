/****************************************************************/
/* SEAL CKKS Gross Pay calculator                               */
/* Author: Majdi Maalej                                         */
/* Parts of code learned from:                                  */
/* 4_CKKS_basics.cpp                                            */
/* GrossPay = (NumberofRegularHours * RegularHourlyRate)        */
/*                +(NumberofOvertimeHours * OvertimeHourlyRate) */
/****************************************************************/
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

	/*****Encoding & Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

    int N = 8192; 
	vector<double> NumberOfRegularHours; 
	vector<double> RegularHourlyRate; 
	vector<double> NumberOfOvertimeHours; 
	vector<double> OvertimeHourlyRate;   	

	for(int i = 0; i < N; i++){
		NumberOfRegularHours.push_back(random_double(40,192));
		RegularHourlyRate.push_back(random_double(9,30));
		NumberOfOvertimeHours.push_back(random_double(0,40));
		OvertimeHourlyRate.push_back(random_double(9,20));
	}
	
    Plaintext plain_regular_hours, plain_regular_rate, plain_overtime_hours, plain_overtime_rate;
	
    encoder.encode(NumberOfRegularHours, scale, plain_regular_hours);
    encoder.encode(RegularHourlyRate, scale, plain_regular_rate);
    encoder.encode(NumberOfOvertimeHours, scale, plain_overtime_hours);
	encoder.encode(OvertimeHourlyRate, scale, plain_overtime_rate);

    Ciphertext enc_regular_hours, enc_regular_rate, enc_overtime_hours, enc_overtime_rate;
	
    encryptor.encrypt(plain_regular_hours, enc_regular_hours);
	encryptor.encrypt(plain_regular_rate, enc_regular_rate);
	encryptor.encrypt(plain_overtime_hours, enc_overtime_hours);
	encryptor.encrypt(plain_overtime_rate, enc_overtime_rate);

	enc_clock = clock() - enc_clock;

    /*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

    Ciphertext enc_StandardPay;
	Ciphertext enc_GrossPay;
	Ciphertext enc_OvertimePay;

    evaluator.multiply(enc_regular_hours, enc_regular_rate, enc_StandardPay);
	evaluator.relinearize_inplace(enc_StandardPay, relin_keys);
	evaluator.rescale_to_next_inplace(enc_StandardPay);

	evaluator.multiply(enc_overtime_hours, enc_overtime_rate, enc_OvertimePay);
	evaluator.relinearize_inplace(enc_OvertimePay, relin_keys);
	evaluator.rescale_to_next_inplace(enc_OvertimePay);

	parms_id_type last_parms_id = enc_StandardPay.parms_id();
	evaluator.mod_switch_to_inplace(enc_OvertimePay, last_parms_id);

	evaluator.add(enc_StandardPay, enc_OvertimePay, enc_GrossPay);

	eval_clock = clock() - eval_clock;

	/*****Decryption & Decoding*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_GrossPay;
	decryptor.decrypt(enc_GrossPay, plain_GrossPay);
	
	vector<double> grossPay;
	encoder.decode(plain_GrossPay, grossPay);

	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "Starting the Gross Pay calculator with " << N << " instances. "<< endl << endl;
	
	cout << "NumberOfRegularHours: " << endl;
	print_vector(NumberOfRegularHours, 10, 4);

	cout << "RegularHourlyRate: " << endl;
	print_vector(RegularHourlyRate, 10, 4);

	cout << "NumberOfOvertimeHours: " << endl;
	print_vector(NumberOfOvertimeHours, 10, 4);
	
	cout << "OvertimeHourlyRate: " << endl;
	print_vector(OvertimeHourlyRate, 10, 4);

	cout << "GrossPay: " << endl;
	print_vector(grossPay, 10, 4);
	
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
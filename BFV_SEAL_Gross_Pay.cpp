/****************************************************************/
/* SEAL BFV batched Gross Pay calculator                        */
/* Author: Majdi Maalej                                         */
/* Parts of code learned from:                                  */
/* 1_bfv_basics.cpp and 2_encoders.cpp                          */
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

	EncryptionParameters parms(scheme_type::bfv);
	size_t poly_modulus_degree = 32768;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 55, 46, 46, 46, 46, 60 }));
	parms.set_plain_modulus(65537);

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
	vector<uint64_t> NumberOfRegularHours(slot_count, 0ULL);    
	vector<uint64_t> RegularHourlyRate(slot_count, 0ULL);               
	vector<uint64_t> NumberOfOvertimeHours(slot_count, 0ULL);     
	vector<uint64_t> OvertimeHourlyRate(slot_count, 0ULL);   	

	for(int r = 0; r < 2; r++){
		for(int c = 0; c < N/2; c++){
			NumberOfRegularHours[r*row_size + c] = random_int(40, 192);
			RegularHourlyRate[r*row_size + c] = random_int(9, 30);
			NumberOfOvertimeHours[r*row_size + c] = random_int(0, 40);
			OvertimeHourlyRate[r*row_size + c] = random_int(9, 20);
		}
	}	
	
	Plaintext plain_regular_hours;
	Plaintext plain_regular_rate;
	Plaintext plain_overtime_hours;
	Plaintext plain_overtime_rate;

	batch_encoder.encode(NumberOfRegularHours, plain_regular_hours);
	batch_encoder.encode(RegularHourlyRate, plain_regular_rate);
	batch_encoder.encode(NumberOfOvertimeHours, plain_overtime_hours);
	batch_encoder.encode(OvertimeHourlyRate, plain_overtime_rate);

	Ciphertext enc_regular_hours;
	Ciphertext enc_regular_rate;
	Ciphertext enc_overtime_hours;
	Ciphertext enc_overtime_rate;

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

	evaluator.multiply(enc_regular_hours, enc_regular_rate, enc_StandardPay);
	evaluator.multiply(enc_overtime_hours, enc_overtime_rate, enc_GrossPay);
	evaluator.add_inplace(enc_GrossPay, enc_StandardPay);

	eval_clock = clock() - eval_clock;

	/*****Decryption & Decoding*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_GrossPay;

	decryptor.decrypt(enc_GrossPay, plain_GrossPay);
	
	vector<uint64_t> grossPay;
	batch_encoder.decode(plain_GrossPay, grossPay);
	
	dec_clock = clock() - dec_clock;
	
	/*****Print*****/
	cout << "Starting the Gross Pay calculator with " << N << " instances. "<< endl << endl;

	cout << "NumberOfRegularHours: " << endl;
	print_matrix(NumberOfRegularHours, row_size);

	cout << "RegularHourlyRate: " << endl;
	print_matrix(RegularHourlyRate, row_size);

	cout << "NumberOfOvertimeHours: " << endl;
	print_matrix(NumberOfOvertimeHours, row_size);
	
	cout << "OvertimeHourlyRate: " << endl;
	print_matrix(OvertimeHourlyRate, row_size);

	cout << "GrossPay: " << endl;
	print_matrix(grossPay, row_size);
	
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
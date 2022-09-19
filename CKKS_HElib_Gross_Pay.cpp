/****************************************************************/
/* HElib CKKS Gross Pay calculator                              */
/* Author: Majdi Maalej                                         */
/* Parts of code learned from:                                  */
/* 01_ckks_basics.cpp                                           */
/* GrossPay = (NumberofRegularHours * RegularHourlyRate)        */
/*                +(NumberofOvertimeHours * OvertimeHourlyRate) */
/****************************************************************/
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <helib/helib.h>
#include <sys/resource.h>
#include <unistd.h>

using namespace std;
using namespace helib;

void print(vector<double> v, long length){
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
	srand(time(NULL));
	
	/*****Set Parameters*****/
	clock_t cc_clock;
	cc_clock = clock();
	
	// Cyclotomic polynomial - defines phi(m).
	unsigned long m = 32768;
	// Number of bits of the modulus chain.
	unsigned long bits = 299;
	// Number of columns of Key-Switching matrix (typically 2 or 3).
	unsigned long c = 3;
	// Number of bits for Precision of of endoded data.
	unsigned long precision = 40;
 
	// Initialize the context.
	
	// This object will hold information about the algebra created from the previously set parameters.
	helib::Context context = helib::ContextBuilder<helib::CKKS>()
                               .m(m)         //cyclotomic polynomial
                               .bits(bits)   //number of bits in the modulo chain
                               .c(c)         //number of columns of Key-Switching matrix (typically 2 or 3).
							   .precision(precision) // bits of precision
                               .build();
							   
	cout << "Security: " << context.securityLevel() << endl; 
	cc_clock = clock() - cc_clock;

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

	SecKey secret_key(context);
	secret_key.GenSecKey();
	PubKey& public_key = secret_key;

	long num_slots = context.getNSlots();
	cout << "Number of slots: " << num_slots << endl; // equal to m/4

	key_clock = clock() - key_clock;

	/*****Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	vector<double> NumberOfRegularHours;
	vector<double> RegularHourlyRate;
	vector<double> NumberOfOvertimeHours;
	vector<double> OvertimeHourlyRate;

	for(int i = 0; i < num_slots; i++){
		NumberOfRegularHours.push_back(random_double(40, 192));
		RegularHourlyRate.push_back(random_double(9, 30));
		NumberOfOvertimeHours.push_back(random_double(0, 40));
		OvertimeHourlyRate.push_back(random_double(9, 20));
	}
	
	PtxtArray ptxt_NumberOfRegularHours(context, NumberOfRegularHours);
	PtxtArray ptxt_RegularHourlyRate(context, RegularHourlyRate);
	PtxtArray ptxt_NumberOfOvertimeHours(context, NumberOfOvertimeHours);
	PtxtArray ptxt_OvertimeHourlyRate(context, OvertimeHourlyRate);

	Ctxt enc_NumberOfRegularHours(public_key);
	Ctxt enc_RegularHourlyRate(public_key);
	Ctxt enc_NumberOfOvertimeHours(public_key);
	Ctxt enc_OvertimeHourlyRate(public_key);
	
	Ctxt enc_StandardPay(public_key);
	Ctxt enc_GrossPay(public_key);
	
	ptxt_NumberOfRegularHours.encrypt(enc_NumberOfRegularHours);
	ptxt_RegularHourlyRate.encrypt(enc_RegularHourlyRate);
	ptxt_NumberOfOvertimeHours.encrypt(enc_NumberOfOvertimeHours);
	ptxt_OvertimeHourlyRate.encrypt(enc_OvertimeHourlyRate);

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

	enc_StandardPay += enc_NumberOfRegularHours;
	enc_StandardPay *= enc_RegularHourlyRate;
	
	enc_GrossPay += enc_NumberOfOvertimeHours;
	enc_GrossPay *= enc_OvertimeHourlyRate;
	
	enc_GrossPay += enc_StandardPay;

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();
	
	PtxtArray ptxt_Result(context);
	ptxt_Result.decrypt(enc_GrossPay, secret_key);

	vector<double> GrossPay;
	ptxt_Result.store(GrossPay);

	dec_clock = clock() - dec_clock;
	
	/*****Print*****/
	cout << "Starting the Gross Pay caluculator with " << num_slots << " instances. "<< endl << endl;

	cout << "NumberOfRegularHours: " << endl;
	print(NumberOfRegularHours, num_slots);

	cout << "RegularHourlyRate: " << endl;
	print(RegularHourlyRate, num_slots);

	cout << "NumberOfOvertimeHours: " << endl;
	print(NumberOfOvertimeHours, num_slots);
	
	cout << "OvertimeHourlyRate: " << endl;
	print(OvertimeHourlyRate, num_slots);

	cout << "GrossPay: " << endl;
	print(GrossPay, num_slots);

	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;
	
	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
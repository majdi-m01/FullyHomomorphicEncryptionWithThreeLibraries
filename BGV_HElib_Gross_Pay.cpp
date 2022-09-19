/****************************************************************/
/* HElib BGV Gross Pay calculator                               */
/* Author: Majdi Maalej                                         */
/* Parts of code learned from:                                  */
/* BGV_general_example.cpp                                      */
/* GrossPay = (NumberofRegularHours * RegularHourlyRate)        */
/*                +(NumberofOvertimeHours * OvertimeHourlyRate) */
/****************************************************************/
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>
#include <helib/helib.h>

using namespace std;
using namespace helib;

void print(Ptxt<BGV> v, long length){
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
	
	/*****Set Parameters*****/
	clock_t cc_clock;
	cc_clock = clock();
	
	// Plaintext prime modulus.
	unsigned long p = 65537;
	// Cyclotomic polynomial - defines phi(m).
	unsigned long m = 32768;
	// Hensel lifting (default = 1).
	unsigned long r = 1;
	// Number of bits of the modulus chain.
	unsigned long bits = 299;
	// Number of columns of Key-Switching matrix (typically 2 or 3).
	unsigned long c = 3;
 
	// Initialize the context.
	
	// This object will hold information about the algebra created from the previously set parameters.
	helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)         //cyclotomic polynomial
                               .p(p)           //prime modulud
                               .r(r)            //hensel lifting
                               .bits(bits)   //number of bits in the modulo chain
                               .c(c)          //number of columns of Key-Switching matrix (typically 2 or 3).
                               .build();
							   
	cout << "Security: " << context.securityLevel() << endl; 
	cc_clock = clock() - cc_clock;

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

	SecKey secret_key(context);
	secret_key.GenSecKey();
	addSome1DMatrices(secret_key);
	PubKey& public_key = secret_key;

	const EncryptedArray& ea = context.getEA();
	long num_slots = ea.size(); 
	cout << "Number of slots: " << num_slots << endl;

	key_clock = clock() - key_clock;

	/*****Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	Ptxt<BGV> NumberOfRegularHours(context);
	Ptxt<BGV> RegularHourlyRate(context);
	Ptxt<BGV> NumberOfOvertimeHours(context);
	Ptxt<BGV> OvertimeHourlyRate(context);

	for(int i = 0; i < num_slots/2; i++){
		NumberOfRegularHours[i] = random_int(40, 192);
		RegularHourlyRate[i] = random_int(9, 30);
		NumberOfOvertimeHours[i] = random_int(0, 40);
		OvertimeHourlyRate[i] = random_int(9, 20);
	}

	Ctxt enc_NumberOfRegularHours(public_key);
	Ctxt enc_RegularHourlyRate(public_key);
	Ctxt enc_NumberOfOvertimeHours(public_key);
	Ctxt enc_OvertimeHourlyRate(public_key);
	
	Ctxt enc_StandardPay(public_key);
	Ctxt enc_GrossPay(public_key);
	
	public_key.Encrypt(enc_NumberOfRegularHours, NumberOfRegularHours);
	public_key.Encrypt(enc_RegularHourlyRate, RegularHourlyRate);
	public_key.Encrypt(enc_NumberOfOvertimeHours, NumberOfOvertimeHours);
	public_key.Encrypt(enc_OvertimeHourlyRate, OvertimeHourlyRate);

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
	
	Ptxt<BGV> GrossPay(context);
	secret_key.Decrypt(GrossPay, enc_GrossPay);

	dec_clock = clock() - dec_clock;
	
	/*****Print*****/
	cout << "Starting the Gross Pay caluculator with " << num_slots << " instances. "<< endl << endl;

	cout << "NumberOfRegularHours: " << endl;
	print(NumberOfRegularHours, num_slots);

	cout << "RegularHourlyRate: " << endl;
	print(RegularHourlyRate, num_slots);

	cout << "NumberOfOvertimeHours: "  << endl;
	print(NumberOfOvertimeHours, num_slots);
	
	cout << "OvertimeHourlyRate: " << endl;
	print(OvertimeHourlyRate, num_slots);

	cout << "GrossPay: "  << endl;
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
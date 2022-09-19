/********************************************/
/* HElib CKKS Luminousity calculator        */
/* Author: Majdi Maalej                     */
/* Parts of code learned from:              */
/* 01_ckks_basics.cpp                       */
/* Luminousity/(4*pi*sigma) = (r^2) * (T^4) */
/********************************************/
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
	cout << "Number of slots: " << num_slots << endl;

	key_clock = clock() - key_clock;

	/*****Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	vector<double> Radius;
	vector<double> SurfaceTemperature;
	
	for(int i = 0; i < num_slots; i++){
		Radius.push_back(random_double(9, 81));
		SurfaceTemperature.push_back(random_double(2, 20));
	}
	
	PtxtArray ptxt_Radius(context, Radius);
	PtxtArray ptxt_SurfaceTemperature(context, SurfaceTemperature);

	Ctxt enc_Radius(public_key);
	Ctxt enc_SurfaceTemperature(public_key);
	Ctxt enc_Result(public_key);
	
	ptxt_Radius.encrypt(enc_Radius);
	ptxt_SurfaceTemperature.encrypt(enc_SurfaceTemperature);

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

	PtxtArray ptxt_one(context);
	ptxt_one *= 0;
	ptxt_one += 1;
	PtxtArray ptxt_zero(context);
	ptxt_zero *= 0;
	
	enc_Result *= ptxt_zero;
	enc_Result += ptxt_one;
	
	enc_Result *= enc_Radius;
	enc_Result *= enc_Radius;
	
	enc_Result *= enc_SurfaceTemperature;
	enc_Result *= enc_SurfaceTemperature;
	enc_Result *= enc_SurfaceTemperature;
	enc_Result *= enc_SurfaceTemperature;

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();
	
	PtxtArray ptxt_Result(context);
	ptxt_Result.decrypt(enc_Result, secret_key);

	vector<double> Result;
	ptxt_Result.store(Result);

	dec_clock = clock() - dec_clock;
	
	/*****Print*****/
	cout << "Starting the ( Luminousity/(4*pi*sigma) ) of a star caluculator with " << num_slots << " instances. "<< endl << endl;

	cout << "Radius: " << endl;
	print(Radius, num_slots);

	cout << "Surface Temperature: " << endl;
	print(SurfaceTemperature, num_slots);

	cout << "Result: " << endl;
	print(Result, num_slots);
		
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
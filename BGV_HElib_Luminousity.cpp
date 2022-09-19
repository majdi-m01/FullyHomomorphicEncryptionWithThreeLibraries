/*****************************************************/
/* HElib BGV Luminousity calculator             */
/* Author: Majdi Maalej                                 */
/* Parts of code learned from:                      */
/* BGV_general_example.cpp                     */
/* Luminousity/(4*pi*sigma) = (r^2) * (T^4)  */
/***************************************************/
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <helib/helib.h>
#include <sys/resource.h>
#include <unistd.h>
#include <helib/replicate.h>

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

int64_t random_int(int64_t min, int64_t max){
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
	unsigned long p = 2147352577;
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

	Ptxt<BGV> Radius(context);
	Ptxt<BGV> SurfaceTemperature(context);
	
	for(int i = 0; i < num_slots/2; i++){
		Radius[i] = random_int(9, 81);
		SurfaceTemperature[i] = random_int(2, 20);
	}

	Ctxt enc_Radius(public_key);
	Ctxt enc_SurfaceTemperature(public_key);
	
	public_key.Encrypt(enc_Radius, Radius);
	public_key.Encrypt(enc_SurfaceTemperature, SurfaceTemperature);
	
	Ctxt enc_Result(public_key);
	
	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();
	
	enc_Result *= 0l;
	enc_Result += 1l;
	
	enc_Radius.multiplyBy(enc_Radius);
	enc_SurfaceTemperature.multiplyBy(enc_SurfaceTemperature);
	enc_SurfaceTemperature.multiplyBy(enc_SurfaceTemperature);
	
	enc_Result.multiplyBy(enc_Radius);
	enc_Result.multiplyBy(enc_SurfaceTemperature);

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();

	Ptxt<BGV> Result(context);
	secret_key.Decrypt(Result, enc_Result);

	dec_clock = clock() - dec_clock;

	/*
	//Luminousity calculator
	vector<long double> Luminousity(ConvertedResult.begin(), ConvertedResult.end());
	const double boltzmann_constant = 1.3806503 * pow(10, -23);
	const double pi = atan(1)*4;
	const double myConstant = 4*boltzmann_constant*pi;
	for(int i=0; i < Luminousity.size(); ++i){
		Luminousity[i] *= myConstant;
	}*/
	
	/*****Print*****/
	cout << "Starting the ( Luminousity/(4*pi*sigma) ) of a star caluculator with " << num_slots << " instances. "<< endl << endl;

	cout << "Radius: " << endl;
	print(Radius, num_slots);
	
	cout << "SurfaceTemperature: " << endl;
	print(SurfaceTemperature, num_slots);
	
	cout << "Result ( Luminousity/(4*pi*sigma) ): " << endl;
	print(Result, num_slots);

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
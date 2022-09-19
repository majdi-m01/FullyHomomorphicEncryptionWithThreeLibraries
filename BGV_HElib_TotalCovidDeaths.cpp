/**********************************************/
/* HElib BGV Total Covid-19 Deaths calculator */
/* Author: Majdi Maalej                       */
/* Parts of code learned from:                */
/* BGV_general_example.cpp                    */
/* Total Deaths = sumOf(DeathsInState_i)      */
/**********************************************/
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <helib/helib.h>
#include <sys/resource.h>
#include <unistd.h>

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
	
	// Plaintext prime modulus
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
	std::cout << "Number of slots: " << num_slots << std::endl;

	key_clock = clock() - key_clock;

	/*****Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	Ptxt<BGV> BW(context), BY(context), BE(context), BB(context), HB(context), HH(context), 
							HE(context), NI(context), MV(context), NW(context), RP(context), SL(context),
									SN(context), ST(context), SH(context), TH(context);

	for(int i = 0; i < num_slots/2; ++i){
		BW[i] = random_int(0, 50);
		BY[i] = random_int(0, 50);
		BE[i] = random_int(0, 50);
		BB[i] = random_int(0, 50);
		HB[i] = random_int(0, 50);
		HH[i] = random_int(0, 50);
		HE[i] = random_int(0, 50);
		NI[i] = random_int(0, 50);
		MV[i] = random_int(0, 50);
		NW[i] = random_int(0, 50);
		RP[i] = random_int(0, 50);
		SL[i] = random_int(0, 50);
		SN[i] = random_int(0, 50);
		ST[i] = random_int(0, 50);
		SH[i] = random_int(0, 50);
		TH[i] = random_int(0, 50);
	}

	Ctxt enc_BW(public_key), enc_BY(public_key), enc_BE(public_key), enc_BB(public_key), 
				enc_HB(public_key), enc_HH(public_key), enc_HE(public_key), enc_NI(public_key), 
					enc_MV(public_key), enc_NW(public_key), enc_RP(public_key), enc_SL(public_key), 
						enc_SN(public_key), enc_ST(public_key), enc_SH(public_key), enc_TH(public_key);
	
	Ctxt enc_TotalDeaths(public_key);
	
	public_key.Encrypt(enc_BW, BW);
	public_key.Encrypt(enc_BY, BY);
	public_key.Encrypt(enc_BE, BE);
	public_key.Encrypt(enc_BB, BB);
	public_key.Encrypt(enc_HB, HB);
	public_key.Encrypt(enc_HH, HH);
	public_key.Encrypt(enc_HE, HE);
	public_key.Encrypt(enc_NI, NI);
	public_key.Encrypt(enc_MV, MV);
	public_key.Encrypt(enc_NW, NW);
	public_key.Encrypt(enc_RP, RP);
	public_key.Encrypt(enc_SL, SL);
	public_key.Encrypt(enc_SN, SN);
	public_key.Encrypt(enc_ST, ST);
	public_key.Encrypt(enc_SH, SH);
	public_key.Encrypt(enc_TH, TH);

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

	enc_TotalDeaths += enc_BW;
	enc_TotalDeaths += enc_BY;
	enc_TotalDeaths += enc_BE;
	enc_TotalDeaths += enc_BB;
	enc_TotalDeaths += enc_HB;
	enc_TotalDeaths += enc_HH;
	enc_TotalDeaths += enc_HE;
	enc_TotalDeaths += enc_NI;
	enc_TotalDeaths += enc_MV;
	enc_TotalDeaths += enc_NW;
	enc_TotalDeaths += enc_RP;
	enc_TotalDeaths += enc_SL;
	enc_TotalDeaths += enc_SN;
	enc_TotalDeaths += enc_ST;
	enc_TotalDeaths += enc_SH;
	enc_TotalDeaths += enc_TH;

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();

	Ptxt<BGV> TotalDeaths(context);
	secret_key.Decrypt(TotalDeaths, enc_TotalDeaths);

	dec_clock = clock() - dec_clock;
	
	/*****Print*****/
	cout << "Starting the total Covid-19 Deaths calculator with " << num_slots << " instances. "<< endl << endl;

	cout << "Baden-Wuerttemberg: " << endl;
	print(BW, num_slots);

	cout << "Bavaria: " << endl;
	print(BY, num_slots);

	cout << "Berlin: " << endl;
	print(BE, num_slots);
	
	cout << "Brandenburg: " << endl;
	print(BB, num_slots);

	cout << "Bremen: " << endl;
	print(HB, num_slots);
	
	cout << "Hamburg: " << endl;
	print(HH, num_slots);
	
	cout << "Hesse: " << endl;
	print(HE, num_slots);
	
	cout << "Lower Saxony: " << endl;
	print(NI, num_slots);
	
	cout << "Mecklenburg-Vorpommern: " << endl;
	print(MV, num_slots);
	
	cout << "North Rhine-Westphalia: " << endl;
	print(NW, num_slots);
	
	cout << "Rhineland-Palatinate: " << endl;
	print(RP, num_slots);
	
	cout << "Saarland: " << endl;
	print(SL, num_slots);

	cout << "Saxony: " << endl;
	print(SN, num_slots);
	
	cout << "Saxony-Anhalt: " << endl;
	print(ST, num_slots);
	
	cout << "Schleswig-Holstein: " << endl;
	print(SH, num_slots);
	
	cout << "Thuringia	: " << endl;
	print(TH, num_slots);
	
	cout << "Total Covid-19 Deaths	: " << endl;
	print(TotalDeaths, num_slots);
	
	cout<< "Memory Usage: " << get_mem_usage() - baseline << endl;
	
	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation            : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
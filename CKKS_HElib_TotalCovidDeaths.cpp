/***********************************************/
/* HElib CKKS Total Covid-19 Deaths calculator */
/* Author: Majdi Maalej                        */
/* Parts of code learned from:                 */
/* 01_ckks_basics.cpp                          */
/* Total Deaths = sumOf(DeathsInState_i)       */
/***********************************************/
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <helib/helib.h>
#include <sys/resource.h>
#include <unistd.h>

using namespace std;
using namespace helib;

void print(vector<long> v, long length){
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
                               .c(c)          //number of columns of Key-Switching matrix (typically 2 or 3).
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
	std::cout << "Number of slots: " << num_slots << std::endl;

	key_clock = clock() - key_clock;

	/*****Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	vector<long> BW, BY, BE, BB, HB, HH, HE, NI, 
				 MV, NW, RP, SL, SN, ST, SH, TH;

	for(int i = 0; i < num_slots; ++i){
		BW.push_back(random_int(0, 50));
		BY.push_back(random_int(0, 50));
		BE.push_back(random_int(0, 50));
		BB.push_back(random_int(0, 50));
		HB.push_back(random_int(0, 50));
		HH.push_back(random_int(0, 50));
		HE.push_back(random_int(0, 50));
		NI.push_back(random_int(0, 50));
		MV.push_back(random_int(0, 50));
		NW.push_back(random_int(0, 50));
		RP.push_back(random_int(0, 50));
		SL.push_back(random_int(0, 50));
		SN.push_back(random_int(0, 50));
		ST.push_back(random_int(0, 50));
		SH.push_back(random_int(0, 50));
		TH.push_back(random_int(0, 50));
	}
	
	PtxtArray ptxt_BW(context, BW), ptxt_BY(context, BY), ptxt_BE(context, BE), ptxt_BB(context, BB), 
						ptxt_HB(context, HB), ptxt_HH(context, HH), ptxt_HE(context, HE), ptxt_NI(context, NI), 
							ptxt_MV(context, MV), ptxt_NW(context, NW), ptxt_RP(context, RP), ptxt_SL(context, SL), 
								ptxt_SN(context, SN), ptxt_ST(context, ST), ptxt_SH(context, SH), ptxt_TH(context, TH);
	
	Ctxt enc_BW(public_key), enc_BY(public_key), enc_BE(public_key), enc_BB(public_key), 
				enc_HB(public_key), enc_HH(public_key), enc_HE(public_key), enc_NI(public_key), 
					enc_MV(public_key), enc_NW(public_key), enc_RP(public_key), enc_SL(public_key), 
						enc_SN(public_key), enc_ST(public_key), enc_SH(public_key), enc_TH(public_key);
	
	Ctxt enc_TotalDeaths(public_key);
	
	ptxt_BW.encrypt(enc_BW);
	ptxt_BY.encrypt(enc_BY);
	ptxt_BE.encrypt(enc_BE);
	ptxt_BB.encrypt(enc_BB);
	ptxt_HB.encrypt(enc_HB);
	ptxt_HH.encrypt(enc_HH);
	ptxt_HE.encrypt(enc_HE);
	ptxt_NI.encrypt(enc_NI);
	ptxt_MV.encrypt(enc_MV);
	ptxt_NW.encrypt(enc_NW);
	ptxt_RP.encrypt(enc_RP);
	ptxt_SL.encrypt(enc_SL);
	ptxt_SN.encrypt(enc_SN);
	ptxt_ST.encrypt(enc_ST);
	ptxt_SH.encrypt(enc_SH);
	ptxt_TH.encrypt(enc_TH);

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
	
	PtxtArray ptxt_TotalDeaths(context);
	ptxt_TotalDeaths.decrypt(enc_TotalDeaths, secret_key);

	vector<long> TotalDeaths;
	ptxt_TotalDeaths.store(TotalDeaths);

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
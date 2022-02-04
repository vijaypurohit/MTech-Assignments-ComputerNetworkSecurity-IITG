/*
 *  Programming Problem 3.25: Cryptography and Network Security Principles and Practice (2017) - Ed. 7th
 *  Computer and Network Security CS549, IITG
 *  Roll Num - 214101058 | Vijay Purohit
 *
 *  Write a program that can perform a letter frequency attack on an additive cipher without human intervention. Your software should produce possible plaintexts in
 *  rough order of likelihood. It would be good if your user interface allowed the user to specify “give me the top 10 possible plaintexts.
 */

#include <iostream>
#include <algorithm>

using namespace std;

// for Linux and Windows Pause and Clear Command
#if defined(_WIN32)
#define PAUSE "pause"
#define CLR "cls"
#elif defined(unix) || defined(__unix__) || defined(__unix)
#define PAUSE "read -p 'Press Enter to continue...' var"
    #define CLR "clear"
#endif

const int NumEngLetters = 26;

void calculate_possibilities(const string &ip_cipher, const int &num_pt)
{
    /*
     * Standard Frequency distribution for the English language
     * Fig 3.5 | William Stalling
     */
    string engLetterByFreqDistribution = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

    string plainTextPoss[num_pt]; // number of plaintext possibilities needed

    unsigned int ip_cipher_length = ip_cipher.length(); // length of input cipher
    int freqCipher[NumEngLetters]={0}; // storing frequency of cipher
    int freqCipherSorted[NumEngLetters]={0}; // cipher frequency sorted order
    int ch_minus; // variable for storing character value

    // Calculate Frequency of letters in cipher text.
    for(char ch: ip_cipher){
        if(ch == ' ') continue;
        if(isupper(ch))
            ch_minus=ch-'A';
        else if(islower(ch))
            ch_minus=ch-'a';
        freqCipher[ch_minus]++;
        freqCipherSorted[ch_minus]++;
    }

    // sort the frequency in decreasing order
    sort(freqCipherSorted, freqCipherSorted+26, greater<int>());

    // for each possibility of plain text
    for(int p=0; p<num_pt; p++){
        string temp_string;

        int cipher_index = -1;
        int shift_distribution=-1;
        int shift; // actual shift doing
        for(int i=0; i<NumEngLetters; i++){
            if(freqCipherSorted[p] == freqCipher[i])
            {
                cipher_index=i;
                freqCipher[i] = freqCipher[i]-freqCipher[i]-1; // so that to ignore it next time and find another possibility
                break;
            }
        }
        if(cipher_index==-1) {
            cout<<"\n\n No More Plain Text Possible.\n";
            break;
        }

        // because standard distribution is given in capital letters, making index zero and then finding the shift with the cipher index
        shift_distribution = engLetterByFreqDistribution[p] - 'A' - cipher_index;

        for(unsigned int i=0; i<ip_cipher_length; i++){
            if(ip_cipher[i]==' ') //if it is space don't evaluate
            {
                temp_string+=ip_cipher[i];
                continue ;
            }

            if(isupper(ip_cipher[i]))
                ch_minus='A';
            else if (islower(ip_cipher[i]))
                ch_minus='a';

            // calculating the shift of each input cipher letter.
            shift = (ip_cipher[i]-ch_minus + shift_distribution)%NumEngLetters;
            if(shift < 0)
                shift +=NumEngLetters;

            temp_string += (char)(shift + (int)ch_minus);
        }

        plainTextPoss[p]=temp_string; // storing the possibility
    }

    // Print the generated 5 possible plaintexts
    for (int i = 0; i < num_pt; i++) {
        cout << plainTextPoss[i] << endl;
    }

}

/********************************************************************************************
	Main Function
********************************************************************************************/
int main()
{
    string ip_cipher_txt;
    int num_plain_txt;

    cout<<"\n Enter Number of Times You want Plain Text Possibilities (1-"<<NumEngLetters-1<<"): ";
        cin>>num_plain_txt;

    cout<<"\n Enter Plain Text String : ";
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    getline(cin, ip_cipher_txt);

    calculate_possibilities(ip_cipher_txt, num_plain_txt);

    cout<<"\n Press Enter To Exit. ";
    cin.get();
    cin.get();
    return 0;
}
/*
 *  Programming Problem 3.23:  Cryptography and Network Security Principles and Practice (2017) - Ed. 7th
 *  Computer and Network Security CS549, IITG
 *  Roll Num - 214101058 | Vijay Purohit
 *
 *  Write a program that can encrypt and decrypt using the general Caesar cipher, also known as an additive cipher
 */

#include <iostream>
#include <limits>

using namespace std;

// for Linux and Windows Pause and Clear Command
#if defined(_WIN32)
    #define PAUSE "pause"
    #define CLR "cls"
#elif defined(unix) || defined(__unix__) || defined(__unix)
    #define PAUSE "read -p 'Press Enter to continue...' var"
    #define CLR "clear"
#endif

/********************************************************************************************
	Caeser Encryption Function C = E(k, p) = (p + k) mod 26
********************************************************************************************/
string encryption_CaeserCipher(int k, string &plain_text)
{
    string output;
    for(char ch: plain_text)
    {

        //uppercase char
        /* shifted char = ch+k
         * normalised shifted char = ch -65 +k
         * (65-90 uppercase chars)  (97-122 lowercase chars)
         * mod val= (ch -65 +k)%25
         * make char again =  mod_val+65
        */
        if(isupper(ch)) {
            output += char(( int(ch) - 65 + k )%26 + 65);
        }
        else if(islower(ch)){ //lower case char
            output += char(( int(ch) - 97 + k )%26 + 97);
        }
        else
            output +=ch;

    }

    return output;
}

/********************************************************************************************
	Caeser Decryption Function p = D(k, C) = (C - k) mod 26
********************************************************************************************/
string decryption_CaeserCipher(int k, string &cipher_text)
{
    string output;
    int normalised, r;
    for(char ch: cipher_text)
    {

        //uppercase char
        /* shifter char = ch+k
         * normalised shifted char = ch -65 +k
         * (65-90 uppercase chars)  (97-122 lowercase chars)
         * mod val= (ch -65 +k)%25
         * make char again =  mod_val+65
         * abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ
        */
        if(isupper(ch)) {
             normalised = ( int(ch) - 65 - k );
             r = normalised %26 >= 0 ? normalised %26  : 26 + normalised %26 ;
            output += char(r + 65);
        }
        else if(islower(ch)){ //lower case char
            normalised = ( int(ch) - 97 - k );
            r = normalised %26 >= 0 ? normalised %26  : 26 + normalised %26 ;
            output += char(r + 97);
        }
        else
        output +=ch;

    }

    return output;
}

/********************************************************************************************
	Main Function
********************************************************************************************/
int main()
{

    char choice;
    string ip_plain_txt, op_plain_txt;  //plain text to encrypt
    string op_cipher_txt, ip_cipher_txt; // cipher text
    int shift_val; //shift value for caeser cipher

    do{
        char ch;

        cout<<endl<<endl<<endl;
        system(PAUSE);
        system(CLR);

        cout<<"\n\n -------- CAESER CIPHER MENU--------";

        cout<<"\n e. Encryption";
        cout<<"\n d. Decryption";

        cout<<"\n\n n. Exit - Bye \n\n --Choice : ";
            cin>>ch;
        cout<<"\n <-------->";

        switch(ch){
            //encryption
            case 'e':
                cout<<"\n Enter Plain Text String : ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                getline(cin, ip_plain_txt);

                cout<<"\n Enter Shift Value \'k\' (1-25) : ";
                    cin>>shift_val;

                op_cipher_txt = encryption_CaeserCipher( shift_val, ip_plain_txt);

                cout<<"\n ENCRYPTION DONE :"
                 << "\n :::::=> Plain Text (input) : "<<ip_plain_txt
                 << "\n :::::=> Shift Value (input) : " <<shift_val
                 << "\n :::::=> Cipher Text (output) : " <<op_cipher_txt;

                break;
            //decryption
            case 'd':
                cout<<"\n Enter Cipher Text String : ";
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                getline(cin, ip_cipher_txt);

                cout<<"\n Enter Shift Value \'k\' (1-25) : ";
                    cin>>shift_val;

                op_plain_txt = decryption_CaeserCipher( shift_val, ip_cipher_txt);

                cout<<"\n DECRYPTION DONE :"
                    << "\n :::::=> Cipher Text (input) : " <<ip_cipher_txt
                    << "\n :::::=> Shift Value (input) : " <<shift_val
                    << "\n :::::=> Plain Text (output) : "<<op_plain_txt;

                break;

            case 'n': cout<<"\n Bye \n"; break;
            default: cout<< "\n--Invalid Choice. Enter Again \n";
        }

        choice=ch;
    }while(choice != 'n');

    cin.get();
    cin.get();
    return 0;
}

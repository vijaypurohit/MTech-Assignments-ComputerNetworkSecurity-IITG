/*
 *  Programming Problem 6.14: Cryptography and Network Security Principles and Practice (2017) - Ed. 7th
 *  Computer and Network Security CS549, IITG
 *  Roll Num - 214101058 | Vijay Purohit
 *
 *  Create software that can encrypt and decrypt using S-AES, as described in Appendix I.
 *  Test data: A binary plaintext of 0110 1111 0110 1011 encrypted with a binary key of 1010 0111 0011 1011 
 *  should give a binary ciphertext of 0000 0111 011 1000. Decryption should work correspondingly.
 *  Input (plaintext) block: 16-bits
 *  Output (ciphertext) block: 16-bits
 *  Key: 16-bits
 *  Rounds: 3
 * https://www.nku.edu/~christensen/simplified%20AES.pdf
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <limits>
#include <unordered_map>

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
        Simplified - Advanced Encryption Standard CLASS
********************************************************************************************/
class SAES
{
    //Round Constant
    const string RC1 = "10000000"; // Left Byte RC[1] = x^3 = 1000
    const string RC2 = "00110000"; // Left Byte RC[2] = x + 1 = 0011
    //S-Box
    string SBox[4][4] = { {"1001","0100","1010","1011"},
                          {"1101","0001","1000","0101"},
                          {"0110","0010","0000","0011"},
                          {"1100","1110","1111","0111"} };
    string invSBox[4][4] = { {"1010","0101","1001","1011"},
                             {"0001","0111","1000","1111"},
                             {"0110","0000","0010","0011"},
                             {"1100","0100","1101","1110"}};

    unordered_map<string,int> stringToInt;
    unordered_map<int,string> intToString;

    const int TextLength = 16;
    const int KeyLength = 16;

    string key0; // round 0 key
    string key1; // round 1 key
    string key2; // round 2 key

    string XOR_OP(const string &, const string &);
    string key_function_g(const string &, const string&);
    string Encryption_Rounds(const string &, const string&, int);
    string Decryption_Rounds(const string &, const string&, int);

public:
    

    SAES()
    {
         key0.resize(KeyLength,'x');
         key1.resize(KeyLength,'x');
         key2.resize(KeyLength,'x');
         stringToInt["00"]=0;
         stringToInt["01"]=1;
         stringToInt["10"]=2;
         stringToInt["11"]=3;
         intToString[0]="00";
         intToString[1]="01";
         intToString[2]="10";
         intToString[3]="11";
    }

    // key generation function
    void SAES_KEY_GENERATION(const string&);
    string SAES_Encryption(const string&);
    string SAES_Decryption(const string&);

    string getKey0(){
        return key0;
    }

    string getKey1(){
        return key1;
    }

    string getKey2(){
        return key2;
    }

    char xor_char(char a, char b, char c='0') {
        if (b == c) 
            return a;
        else if(a == '0')
            return '1';
        else
            return '0';
    };

};

/********************************************************************************************
        S-AES Encryption Function
********************************************************************************************/
string SAES::SAES_Encryption(const string& ip)
{
    
/**** ROUND 0 : ADD ROUND KEY *****/ 
    string cipherOp = XOR_OP(ip, key0);
/**** ROUND 1 *****/ 
    cipherOp = Encryption_Rounds(cipherOp, key1, 1);
/**** ROUND 2 *****/ 
    cipherOp = Encryption_Rounds(cipherOp, key2, 2);

    return cipherOp;
}

/********************************************************************************************
        S-AES Decryption Function
********************************************************************************************/
string SAES::SAES_Decryption(const string& ip)
{
    
/**** ROUND 0 : ADD ROUND KEY *****/ 
    string plainText = XOR_OP(ip, key2);
/**** ROUND 1 *****/ 
    plainText = Decryption_Rounds(plainText, key1, 1);
/**** ROUND 2 *****/ 
    plainText = Decryption_Rounds(plainText, key0, 2);

    return plainText;
}

/********************************************************************************************
        Rounds Used in Encryption
********************************************************************************************/
string SAES::Encryption_Rounds(const string &text, const string& key, int round)
{
    int dim = 2; // Matrix Dimensions
    string StateM [dim][dim]; // State matrix.

    StateM[0][0] = text.substr(0,4); // Nibble 0 is text 0 to 3 bits
    StateM[0][1] = text.substr(8,4); // Nibble 2 is text 8 to 11 bits
    StateM[1][0] = text.substr(4,4); // Nibble 1 is text 4 to 7 bits
    StateM[1][1] = text.substr(12,4); // Nibble 3 is text 12 to 15 bit

    // Nibble Substitution
    int sub_row, sub_col;

    for(int i=0; i<dim; i++)
    {
        for(int j=0; j<dim; j++)
        {
            sub_row = stringToInt[StateM[i][j].substr(0,2)]; // Nibble first two bits are row index for sBox. 
            sub_col = stringToInt[StateM[i][j].substr(2,2)]; // Nibble last two bits are col index for sBox. 
            StateM[i][j] = SBox[sub_row][sub_col];
        }
    }
    
    // Shift Rows N3 <--> N1 One Nibble Circular shift of the second row
    StateM[1][0].swap(StateM[1][1]);


  string outputM[dim][dim]={{StateM[0][0], StateM[0][1]}, 
                            {StateM[1][0], StateM[1][1]}};

    // Mix Column Using XOR Operation Alternative
   if(round != 2)
   {
       for(int i=0; i<dim; i++)
        {
             outputM[0][i][0] =  xor_char(StateM[0][i][0], StateM[1][i][2]); // b0 = b0^b6
             outputM[0][i][1] =  xor_char(StateM[0][i][1], StateM[1][i][0], StateM[1][i][3]); // b1 = b1^b4^b7
             outputM[0][i][2] =  xor_char(StateM[0][i][2], StateM[1][i][0], StateM[1][i][1]); // b2 = b2^b4^b5
             outputM[0][i][3] =  xor_char(StateM[0][i][3], StateM[1][i][1]); // b3 = b3^b5

             outputM[1][i][0] =  xor_char(StateM[0][i][2], StateM[1][i][0]); // b4 = b2^b4
             outputM[1][i][1] =  xor_char(StateM[0][i][0], StateM[0][i][3], StateM[1][i][1]); // b5 = b0^b3^b5
             outputM[1][i][2] =  xor_char(StateM[0][i][0], StateM[0][i][1], StateM[1][i][2]); // b6 = b0^b1^b6
             outputM[1][i][3] =  xor_char(StateM[0][i][1], StateM[1][i][3]); // b7 = b1^b7
        }
    }

    // Add Round Key
    string op =  outputM[0][0] + outputM[1][0] +  outputM[0][1] +  outputM[1][1];
    op = XOR_OP(op, key);

    return op;
}

/********************************************************************************************
        Rounds Used in Decryption
********************************************************************************************/
string SAES::Decryption_Rounds(const string &text, const string& key, int round)
{
    int dim = 2; // Matrix Dimensions
    string StateM [dim][dim]; // State matrix.

    StateM[0][0] = text.substr(0,4); // Nibble 0 is text 0 to 3 bits
    StateM[0][1] = text.substr(8,4); // Nibble 2 is text 8 to 11 bits
    StateM[1][0] = text.substr(4,4); // Nibble 1 is text 4 to 7 bits
    StateM[1][1] = text.substr(12,4); // Nibble 3 is text 12 to 15 bit

    // Inverse Shift Rows N3 <--> N1 One Nibble Circular shift of the second row
    StateM[1][0].swap(StateM[1][1]);


    // Inverse Nibble Substitution
    int sub_row, sub_col;

    for(int i=0; i<dim; i++)
    {
        for(int j=0; j<dim; j++)
        {
            sub_row = stringToInt[StateM[i][j].substr(0,2)]; // Nibble first two bits are row index for sBox. 
            sub_col = stringToInt[StateM[i][j].substr(2,2)]; // Nibble last two bits are col index for sBox. 
            StateM[i][j] = invSBox[sub_row][sub_col];
        }
    }

    // Add Round Key
    string op =  StateM[0][0] + StateM[1][0] +  StateM[0][1] +  StateM[1][1];
    op = XOR_OP(op, key);
    
// Inverse Mix Column Using XOR Operation
   if(round != 2)
   { 
     string temp = op;
       for(int i=0; i<TextLength; i=i+8)
        {
             temp[i+0] =  xor_char(op[i+3], op[i+5]); // k0 = k3^k5
             temp[i+1] =  xor_char(op[i+0], op[i+6]); // k1 = k0^k6
             temp[i+2] =  xor_char(op[i+1], op[i+4], op[i+7]); // k2 = k1^k4^k7
             temp[i+3] =  xor_char(op[i+2], op[i+3], op[i+4]); // k3 = k2^k3^k4
             temp[i+4] =  xor_char(op[i+1], op[i+7]); // k4 = k1^k7
             temp[i+5] =  xor_char(op[i+2], op[i+4]); // k5 = k2^k4
             temp[i+6] =  xor_char(op[i+0], op[i+3], op[i+5]); // k6 = k0^k3^k5
             temp[i+7] =  xor_char(op[i+0], op[i+6], op[i+7]); // k7 = k0^k6^k7
        }
        op = temp;
    }

    return op;
}//Decryption_Rounds

/********************************************************************************************
    SAES Key Expansion and Generation
********************************************************************************************/
void SAES::SAES_KEY_GENERATION(const string& key)
{
    // key0
    string w0 = key.substr(0,8); // w_0 is key 0 to 7 bits 
    string w1 = key.substr(8,8); // w_1 is key 8 to 15 bits

    key0 = w0+w1;

    //key1
    string w1g = key_function_g(w1, RC1);

    string w2 = XOR_OP(w0, w1g);
    string w3 = XOR_OP(w2, w1);

    key1 = w2+w3;

    //key2
    string w3g = key_function_g(w3, RC2);

    string w4 = XOR_OP(w2, w3g);
    string w5 = XOR_OP(w4, w3);

    key2 = w4+w5;

}

/********************************************************************************************
    Key Transformation Function g used in SAES
********************************************************************************************/
string SAES::key_function_g(const string &w, const string& RC)
{
    string N0 = w.substr(0,4); // Nibble 0 is w 0 to 3 bits
    string N1 = w.substr(4,4); // Nibble 1 is w 4 to 7 bits

    int sub_row, sub_col;
    sub_row = stringToInt[N1.substr(0,2)]; // Nibble first two bits are row index for sBox. 
    sub_col = stringToInt[N1.substr(2,2)]; // Nibble last two bits are col index for sBox. 


    string N1_ = SBox[sub_row][sub_col];

    sub_row = stringToInt[N0.substr(0,2)]; // Nibble first two bits are row index for sBox. 
    sub_col = stringToInt[N0.substr(2,2)]; // Nibble last two bits are col index for sBox. 

    string N0_ = SBox[sub_row][sub_col];

    string w_ = N1_+N0_; // Swapping of Nibble

    string output = XOR_OP(w_, RC);
    return output;
}

/********************************************************************************************
    XOR Operation between two texts
********************************************************************************************/
string SAES::XOR_OP(const string &t1, const string &t2){
    string result_xor;
    for(int i=0; i<t1.length(); i++){
        if(t1[i] == t2[i])
            result_xor.push_back('0');
        else
            result_xor.push_back('1');
    }
    return result_xor;
}

/********************************************************************************************
    Main Function
********************************************************************************************/
int main()
{
    char choice;
    string ip_plain_txt, op_plain_txt;  //plain txt to encrypt
    string op_cipher_txt, ip_cipher_txt;
    string key;

    SAES *obj = new SAES();
    do{
        char ch;

        cout<<endl<<endl<<endl;
        system(PAUSE);
        system(CLR);

        cout<<"\n ---------------- SAES Encryption and Decryption MENU ----------------";

        cout<<"\n e. SAES Encryption";
        cout<<"\n d. SAES Decryption";

        cout<<"\n\n n. Exit - Bye \n\n --Choice : ";
            cin>>ch;
        cout<<"\n <-------->";

        switch(ch){
    //encryption
            case 'e':
                cout<<"\n Enter Plain Text String (16-bits) : ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                getline(cin,ip_plain_txt);

                cout<<"\n Enter Key String (16-bits) : ";
                getline(cin,key);

               // ip_plain_txt="0110111101101011";  //--> op_cipher_txt="0000011100111000";
               // key="1010011100111011";

                obj->SAES_KEY_GENERATION(key);
                op_cipher_txt = obj->SAES_Encryption(ip_plain_txt);

                cout<<"\n SAES ENCRYPTION DONE :"
                    << "\n :::::=> Plain Text (input) : "<<ip_plain_txt
                    << "\n :::::=> Key0 (input) : " <<obj->getKey0()
                    << "\t:::=> Key1 : "<<obj->getKey1()
                    << "\t:::=> Key2  : " <<obj->getKey2()
                    << "\n :::::=> Cipher Text (output) : " <<op_cipher_txt;

                break;
    //decryption
            case 'd':
                cout<<"\n Enter Cipher Text String : ";
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                getline(cin, ip_cipher_txt);

                cout<<"\n Enter Key String (16-bits) : ";
                    cin>>key;
                // ip_cipher_txt="0000011100111000";
                //  key="1010011100111011";

                obj->SAES_KEY_GENERATION(key);
                op_plain_txt = obj->SAES_Decryption(ip_cipher_txt);

                cout<<"\n SAES DECRYPTION DONE :"
                    << "\n :::::=> Cipher Text (input) : " <<ip_cipher_txt
                    << "\n :::::=> Key0 (input) : " <<obj->getKey0()
                    << "\t:::=> Key1 : "<<obj->getKey1()
                    << "\t:::=> Key2  : " <<obj->getKey2()
                    << "\n :::::=> Plain Text (output) : "<<op_plain_txt;

                break;

            case 'n': cout<<"\n Bye \n"; break;
            default: cout<< "\n--Invalid Choice. Enter Again \n";
        }

        choice=ch;
    }while(choice != 'n');

    delete obj;
    cout<<"\n Press Enter To Exit. ";
    cin.get();
    cin.get();
    return 0;
}

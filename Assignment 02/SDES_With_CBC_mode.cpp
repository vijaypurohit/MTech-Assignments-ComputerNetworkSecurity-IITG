/*
 *  Programming Problem 7.19: Cryptography and Network Security Principles and Practice (2017) - Ed. 7th
 *  Computer and Network Security CS549, IITG
 *  Roll Num - 214101058 | Vijay Purohit
 *
 *  Create software that can encrypt and decrypt in CIPHER BLOCK CHAINING mode using the following cipher: S-DES.
 *  Test data for S-DES using a binary initialization vector of 1010 1010. 
 *  A binary plaintext of 0000 0001 0010 0011 encrypted with a binary key of 01111 11101 
 *  should give a binary ciphertext of 1111 0100 0000 1011. Decryption should work correspondingly.
 *  
 *  In CBC scheme, the input to the encryption algorithm is the XOR of the current plain text block and 
 *  the preceding ciphertext block; the same key is used for each block.
 *  last block be padded to a full b bits if it is a partial block.
 *  IV: 8-bits (1010 1010)
 *  Input (plaintext) block: in 8-bits
 *  Encrypt Block Function: SDES
 *  Encrypt Block Key: Key
 *  Key: 10-bits
 */


#include <iostream>
#include <string>
#include <cstdlib>
#include <limits>
#include <cmath>

using namespace std;

// for Linux and Windows Pause and Clear Command
#if defined(_WIN32)
#define PAUSE "pause"
#define CLR "cls"
#elif defined(unix) || defined(__unix__) || defined(__unix)
#define PAUSE "read -p 'Press Enter to continue...' var"
    #define CLR "clear"
#endif


class SDES
{
//  P10 (permutate)
    int P10[10] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
//    P8 (select and permutate)
    int P8[8] = { 6, 3, 7, 4, 8, 5, 10, 9 };
//    P4 (permutate)
    int P4[4] = {2, 4, 3, 1};
//    IP (initial permutation)
    int IP[10] = {2, 6, 3, 1, 4, 8, 5, 7};
// inverse of IP
    int IP_inv[10] = { 4, 1, 3, 5, 7, 2, 8, 6 };
//    EP (expand and permutate)
    int EP[8] = { 4, 1, 2, 3, 2, 3, 4, 1 };
    //S-Box
    int S0[4][4] = { { 1, 0, 3, 2 },
                     { 3, 2, 1, 0 },
                     { 0, 2, 1, 3 },
                     { 3, 1, 3, 2 } };
    int S1[4][4] = { { 0, 1, 2, 3 },
                     { 2, 0, 1, 3 },
                     { 3, 0, 1, 0 },
                     { 2, 1, 0, 3 } };

    const int TextLength = 8;
    const int KeyLength = 10;
    const int KeyLengthINRounds = 8;

    // left shift
    void LeftShift(string &, int ) const;

    
    static int getDecimalValue(const string& );
    static string getBinaryValue(const int& );
    string SubstitutionBox(const string &, int );
    void Function_fk( string &,  string &, const string &);

public:
    string key1; // round 1 key
    string key2; // round 2 key
    string funcFkOutput;

    SDES()
    {
         key1.resize(KeyLengthINRounds,'x');
         key2.resize(KeyLengthINRounds,'x');
         funcFkOutput.resize(TextLength,'x');
    }

    static string XOR_OP(const string &, const string &, int );

    // key generation function
    void SDES_KEY_GENERATION(const string& );

    // encryption function
    string SDES_ENCRYPTION_DECRYPTION(const string& text, const string& k1, const string& k2);

    string getKey1(){
        return key1;
    }
    string getKey2(){
        return key2;
    }
};

/********************************************************************************************
	Left Shift function, taking input text and number of times required to shift
********************************************************************************************/
void SDES::LeftShift(string &t, int shift_times) const {
    int half_keyLength = KeyLength/2;
    while(shift_times>0) {
        char tLeft = t[0];
        char tRight = t[half_keyLength];
        for (int i = 0; i < half_keyLength-1; i++) {
            t[i] = t[i + 1];
            t[half_keyLength + i] = t[half_keyLength + i + 1];
        }
        t[half_keyLength-1] = tLeft;
        t[KeyLength-1] = tRight;
        shift_times--;
    }

}

/********************************************************************************************
	SDES Key Generation Function
********************************************************************************************/
void SDES::SDES_KEY_GENERATION(const string& key_ip)
{
    string key_op(KeyLength,'x');;

    //  P10 Operation
    for(int i=0; i<KeyLength; i++){
        key_op[i] = key_ip[P10[i]-1];
    }
    LeftShift(key_op, 1);

    //  P8 Operation
    for(int i=0; i<KeyLengthINRounds; i++){
        key1[i] =  key_op[P8[i]-1];
    }

    LeftShift(key_op, 2);

    //  P8 Operation
    for(int i=0; i<KeyLengthINRounds; i++){
        key2[i] =  key_op[P8[i]-1];
    }


}

/********************************************************************************************
	XOR Operation between two texts
********************************************************************************************/
string SDES::XOR_OP(const string &t1, const string &t2, int len){
    string result_xor;
    for(int i=0; i<len; i++){
        if(t1[i] == t2[i])
            result_xor.push_back('0');
        else
            result_xor.push_back('1');
    }
    return result_xor;
}

/********************************************************************************************
	Return Decimal Value of the two digit binary
********************************************************************************************/
int SDES::getDecimalValue(const string& twoDigitBinary)
{
    if(twoDigitBinary=="00")
        return 0;
    if(twoDigitBinary=="01")
        return 1;
    if(twoDigitBinary=="10")
        return 2;
    if(twoDigitBinary=="11")
        return 3;
    return -1;
}

/********************************************************************************************
	Return Binary Value of the decimal digit
********************************************************************************************/
string SDES::getBinaryValue(const int& decimal)
{
    if(decimal==0)
        return "00";
    if(decimal==1)
        return "01";
    if(decimal==2)
        return "10";
    if(decimal==3)
        return "11";
    return "-2";
}

/********************************************************************************************
	Substitution function, taking input string to index and box num of the substitution
********************************************************************************************/
string SDES::SubstitutionBox(const string &t, int box_num)
{
    string row_box, col_box;
    row_box.push_back(t[0]); row_box.push_back(t[3]);
    col_box.push_back(t[1]); col_box.push_back(t[2]);

    int s_ri = getDecimalValue(row_box);
    int s_ci = getDecimalValue(col_box);

    if(box_num == 0)
        return getBinaryValue(S0[s_ri][s_ci]);
    else if(box_num == 1)
        return getBinaryValue(S1[s_ri][s_ci]);
    else
        return "-1";
}

/********************************************************************************************
	Function Fk during the SDES Cipher Text generation
********************************************************************************************/
void SDES::Function_fk( string &left_txt,  string &right_txt, const string &k)
{
    int half_TextLength = TextLength/2;
    string EP_Text(TextLength,'x');
    string EP_Key_XoR(TextLength,'x');
    string EP_Key_XoR_left(half_TextLength,'x');
    string EP_Key_XoR_right(half_TextLength,'x');
    string sBoxOutput(half_TextLength,'x');
    string sBoxOutputP4(half_TextLength,'x');
    string P4_LeftStr_XoR(half_TextLength,'x');

    // EP Operation
    for(int i=0; i<TextLength; i++){
        EP_Text[i] =  right_txt[EP[i]-1];
    }

    EP_Key_XoR = XOR_OP(EP_Text, k, TextLength);

    for(int i=0; i<half_TextLength; i++){
        EP_Key_XoR_left[i] =  EP_Key_XoR[i];
        EP_Key_XoR_right[i] =  EP_Key_XoR[i+half_TextLength];
    }

    string SBox_Left_Val = SubstitutionBox(EP_Key_XoR_left, 0);
    string SBox_Right_Val = SubstitutionBox(EP_Key_XoR_right, 1);

    sBoxOutput= (SBox_Left_Val)+(SBox_Right_Val);

    for(int i=0; i<half_TextLength; i++){
        sBoxOutputP4[i] =  sBoxOutput[P4[i]-1];
    }

    P4_LeftStr_XoR = XOR_OP(sBoxOutputP4,left_txt, half_TextLength);

    for(int i=0; i<half_TextLength; i++){
        left_txt[i] =  P4_LeftStr_XoR[i];
        right_txt[i] =  right_txt[i];
    }
}

/********************************************************************************************
	SDES Encryption Decryption
********************************************************************************************/
string SDES::SDES_ENCRYPTION_DECRYPTION(const string& text, const string& k1, const string& k2)
{

    int half_TextLength = TextLength/2;
    string IP_Left(half_TextLength,'x'), IP_Right(half_TextLength,'x');
    string SW_Left(half_TextLength,'x'), SW_Right(half_TextLength,'x');
    string IP_Text(TextLength,'x');
    string output_txt(TextLength,'x');
    // IP Operation
    for(int i=0; i<TextLength; i++){
        IP_Text[i] =  text[IP[i]-1];
    }

    for(int i=0; i<half_TextLength; i++){
        IP_Left[i] =  IP_Text[i];
        IP_Right[i] =  IP_Text[i+half_TextLength];
    }

    Function_fk(IP_Left, IP_Right, k1);
    // Swapping by changing Arguments
    Function_fk(IP_Right, IP_Left, k2);

    string func_fk_text = IP_Right+IP_Left;
    for(int i=0; i<TextLength; i++){
        output_txt[i] =  func_fk_text[IP_inv[i]-1];
    }
    return output_txt;
}


/********************************************************************************************
    Cipher Block Chaining Class
********************************************************************************************/
class CBCWithSDES 
{
    string IV = "10101010"; // initial vector for CBC Mode
    const int CBCBlockLength = IV.length();

    SDES *sdes = new SDES();
    public:
        string CBCEncryption(string, string);
        string CBCDecryption(string, string);


        string getSDESKey1(){
            return sdes->getKey1();
        }
        string getSDESKey2(){
            return sdes->getKey2();
        }

};

/********************************************************************************************
    CBC Encryption Function with SDES, Takes Ip plain text and Key and return cipher text.
********************************************************************************************/
string CBCWithSDES::CBCEncryption(string ip, string key)
{

    sdes->SDES_KEY_GENERATION(key);

    int ipLength = ip.length();
    int numOfBlocks = ceil((ipLength*1.0)/CBCBlockLength);
    string op="";
    string partialCipher = IV, partialIP="";

    // Last Block We have to Put Padding.
    int mod = ipLength % CBCBlockLength;
    if( mod != 0)
    {
        int paddLength = CBCBlockLength - mod; // cout<<paddLength<<" pl;";
        ip.insert(ipLength, paddLength, '0'); // adding padding at the end.
    }


    for(int i=1; i<=numOfBlocks; i++)
    {
        partialIP = ip.substr((i-1)*CBCBlockLength,CBCBlockLength);
        // cout<<endl<<partialIP;
        // if(i==1)
            partialIP = sdes->XOR_OP(partialCipher, partialIP, CBCBlockLength);
        // cout<<endl<<partialIP;

        partialCipher = sdes->SDES_ENCRYPTION_DECRYPTION(partialIP, sdes->getKey1(), sdes->getKey2());
        // cout<<endl<<partialCipher;

        op += partialCipher;
    }

    return op;
}

/********************************************************************************************
    CBC Decryption Function with SDES, Takes Ip cipher text and Key and return plain text
********************************************************************************************/
string CBCWithSDES::CBCDecryption(string ip, string key)
{

    // cout<<endl<<"ip "<<ip;
    sdes->SDES_KEY_GENERATION(key);
 // cout<<endl<<"ip "<<ip;

    int ipLength = ip.length();
    int numOfBlocks = ceil((ipLength*1.0)/CBCBlockLength);
    string op="";
    string partialText = "", partialCipher="", prevCipher=IV;

    // // Last Block We have to Put Padding.
    // if(ipLength % CBCBlockLength != 0)
    // {
    //     int paddLength = CBCBlockLength - ipLength % CBCBlockLength; // cout<<paddLength<<" pl;";
    //     ip.insert(ipLength, paddLength, '0'); // adding padding at the end.
    // }


    for(int i=1; i<=numOfBlocks; i++)
    {
        partialCipher = ip.substr((i-1)*CBCBlockLength,CBCBlockLength);
 // cout<<endl<<"partialCipher "<<partialCipher;
        partialText = sdes->SDES_ENCRYPTION_DECRYPTION(partialCipher, sdes->getKey2(), sdes->getKey1());
 // cout<<endl<<"partialText1 "<<partialCipher;
        partialText = sdes->XOR_OP(prevCipher, partialText,  CBCBlockLength);
 // cout<<endl<<"partialText2 "<<partialCipher;
        prevCipher = partialCipher;

        op += partialText;
    }

    return op;
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

    string IV = "10101010"; // initial vector for CBC Mode
    int CBCBlockLength = IV.length();

    // SDES *obj = new SDES();

    CBCWithSDES *cb = new CBCWithSDES();

    do{
        char ch;

        cout<<endl<<endl<<endl;
        system(PAUSE);
        system(CLR);

        cout<<"\n ---------------- Cipher Block Chaining Mode With SDES MENU ----------------";

        cout<<"\n e. Encryption";
        cout<<"\n d. Decryption";

        cout<<"\n\n n. Exit - Bye \n\n --Choice : ";
            cin>>ch;
        cout<<"\n <-------->";

        switch(ch){
            //encryption
            case 'e':
                cout<<"\n Enter Plain Text String: ";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                getline(cin,ip_plain_txt);

                cout<<"\n Enter Key String (10-bits) : ";
                getline(cin,key);

                // ip_plain_txt="0000000100100011";  //   00000001  00100011 --> op_cipher_txt="1111010000001011";
                // key="0111111101";

                op_cipher_txt = cb->CBCEncryption(ip_plain_txt, key);

                cout<<"\n CBC With SDES ENCRYPTION DONE :"
                    << "\n :::::=> Plain Text (input) : "<<ip_plain_txt
                    << "\n :::::=> SDES Key (input) : " <<key
                    << "\t:::=> SDES Key1 : "<<cb->getSDESKey1()
                    << "\t:::=> SDES Key2  : " <<cb->getSDESKey2()
                    << "\n :::::=> Cipher Text (output) : " <<op_cipher_txt;

                break;
                //decryption
            case 'd':
                cout<<"\n Enter Cipher Text String : ";
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                getline(cin, ip_cipher_txt);

                cout<<"\n Enter Key String (10-bits) : ";
                    cin>>key;

                // ip_cipher_txt="1111010000001011"; //11110100 00001011 --> op_cipher_txt="0000000100100011";
                // key="0111111101";

                op_plain_txt = cb->CBCDecryption(ip_cipher_txt, key);

                cout<<"\n CBC With SDES DECRYPTION DONE :"
                    << "\n :::::=> Cipher Text (input) : " <<ip_cipher_txt
                    << "\n :::::=> SDES Key (input) : " <<key
                    << "\t:::=> SDES Key1 : "<<cb->getSDESKey1()
                    << "\t:::=> SDES Key2  : " <<cb->getSDESKey2()
                    << "\n :::::=> Plain Text (output) : "<<op_plain_txt;

                break;

            case 'n': cout<<"\n Bye \n"; break;
            default: cout<< "\n--Invalid Choice. Enter Again \n";
        }

        choice=ch;
    }while(choice != 'n');

    delete cb;

    cout<<"\n Press Enter To Exit. ";
    cin.get();
    cin.get();
    return 0;
}

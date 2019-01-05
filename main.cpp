#include <iostream>
#include <string>
#include <vector>
#include<stdio.h>
#include "AES_CxDecipher.h"
#include "fstreamExtension.h"

using namespace std;

int main()
{
/*    uint8_t byte;

    fstreamExtension f("C:\\Users\\lenovo\\Desktop\\QBFdata.cipher", ios::in|ios::binary);
    f.fileName("C:\\Users\\lenovo\\Desktop\\QBFdata.cipher");
    long long fileSize = f.fileSize();

    while(f >> byte)
        cout << (double)f.tellg() / (double)fileSize << "\n";*/

    AES_CxDecipher cipher(AES_CxDecipher::AES128);
    const uint8_t k[16] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
    cipher.DecryptFile("C:\\Users\\lenovo\\Desktop\\QBFdata.cipher", "C:\\Users\\lenovo\\Desktop", k);
}

//"C:\\Users\\lenovo\\Desktop\\QBFdata.cipher"

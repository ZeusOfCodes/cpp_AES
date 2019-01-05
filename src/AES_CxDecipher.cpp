#include <algorithm>
#include <random>
#include <functional>
#include "fstreamExtension.h"
#include "AES_CxDecipher.h"

///FUNCTIONS TO PROCESS INPUT FILE PATH/
std::string fileNameFromPath(std::string path)
{
    int pos = path.find_last_of('\\');
    return path.substr(pos + 1);
}

std::string fileNameFromExt(std::string name)
{
    int pos = name.find('.');
    return name.substr(0, pos);
}

std::string extensionFromFileName(std::string name)
{
    int pos = name.find('.');
    return name.substr(pos);
}

std::string createCipherFilePath(std::string inputFile,std::string directory)
{
    std::string temp = directory;
    temp.append("\\");
    temp.append(fileNameFromExt(fileNameFromPath(inputFile)));
    temp.append(".cipher");
    return temp;
}

void stringToBytes(std::string extension, uint8_t* const extensionInHex)
{
    uint8_t extensionBlock[16];
    std::vector<uint8_t> store(extension.begin(), extension.end());

    for(int i = 0; i < 16; i++)
    {
        while(i < store.size())
            {
                extensionInHex[i] = store[i];
                i++;
            }
        extensionInHex[i] = 0x00;
    }
}

std::string bytesToString(const uint8_t* const bytesArray)
{
    std::vector<uint8_t> store;
    for(int i = 0; i < 16; i++)
        store.push_back(bytesArray[i]);
    std::string extension(store.begin(), store.end());
    return extension;
}
/*
void hexDisplay(uint8_t state[16])
{
    char x[2];

    sprintf(x, "%x", state[0]); std::cout << x <<"\t";
    sprintf(x, "%x", state[1]); std::cout << x <<"\t";
    sprintf(x, "%x", state[2]); std::cout << x <<"\t";
    sprintf(x, "%x", state[3]); std::cout << x <<"\n";
    sprintf(x, "%x", state[4]); std::cout << x <<"\t";
    sprintf(x, "%x", state[5]); std::cout << x <<"\t";
    sprintf(x, "%x", state[6]); std::cout << x <<"\t";
    sprintf(x, "%x", state[7]); std::cout << x <<"\n";
    sprintf(x, "%x", state[8]); std::cout << x <<"\t";
    sprintf(x, "%x", state[9]); std::cout << x <<"\t";
    sprintf(x, "%x", state[10]); std::cout << x <<"\t";
    sprintf(x, "%x", state[11]); std::cout << x <<"\n";
    sprintf(x, "%x", state[12]); std::cout << x <<"\t";
    sprintf(x, "%x", state[13]); std::cout << x <<"\t";
    sprintf(x, "%x", state[14]); std::cout << x <<"\t";
    sprintf(x, "%x", state[15]); std::cout << x <<"\n";
    std::cout << "\n\n";
}
*/
/*
void hexDisplay(uint8_t state[4][4])
{
    char x[2];

    sprintf(x, "%x", state[0][0]); std::cout << x <<"\t";
    sprintf(x, "%x", state[0][1]); std::cout << x <<"\t";
    sprintf(x, "%x", state[0][2]); std::cout << x <<"\t";
    sprintf(x, "%x", state[0][3]); std::cout << x <<"\n";
    sprintf(x, "%x", state[1][0]); std::cout << x <<"\t";
    sprintf(x, "%x", state[1][1]); std::cout << x <<"\t";
    sprintf(x, "%x", state[1][2]); std::cout << x <<"\t";
    sprintf(x, "%x", state[1][3]); std::cout << x <<"\n";
    sprintf(x, "%x", state[2][0]); std::cout << x <<"\t";
    sprintf(x, "%x", state[2][1]); std::cout << x <<"\t";
    sprintf(x, "%x", state[2][2]); std::cout << x <<"\t";
    sprintf(x, "%x", state[2][3]); std::cout << x <<"\n";
    sprintf(x, "%x", state[3][0]); std::cout << x <<"\t";
    sprintf(x, "%x", state[3][1]); std::cout << x <<"\t";
    sprintf(x, "%x", state[3][2]); std::cout << x <<"\t";
    sprintf(x, "%x", state[3][3]); std::cout << x <<"\n";
    std::cout << "\n\n";
}
*/
///INITIALIZATION OF CONST DATA MEMBERS/
const uint8_t AES_CxDecipher::S_BOX[256] =    ///static
            {
            ///  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F   /
                 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
            };

const uint8_t AES_CxDecipher::invS_BOX[256] =    ///static
            {
           ///  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F   /
                0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
            };

const uint8_t AES_CxDecipher::R_CON[11] =    //static
            {
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 ///required R_CON values for AES implementation/
            };

const uint8_t AES_CxDecipher::verify[16] =
            {
                0x1e, 0x6f, 0x24, 0xb8, 0xce, 0xf4, 0x91, 0x4b, 0x0d, 0x14, 0x28, 0xe2, 0x63, 0x8f, 0x70, 0xdc
            };

AES_CxDecipher::AES_CxDecipher(const uint8_t bitMode)
{
        if(bitMode == AES_CxDecipher::AES128){ this -> Nk = 4; this -> Nr = 10; }
        else if(bitMode == AES_CxDecipher::AES192){ this -> Nk = 6; this -> Nr = 12; }
        else if(bitMode == AES_CxDecipher::AES256){ this -> Nk = 8; this -> Nr = 14; }
}


///WRAPPER ROUTINES/
void AES_CxDecipher::EncryptFile(const char* inputFilePath, const char* cipherFilePath, const uint8_t* key)
{
    fstreamExtension inputFile(inputFilePath, std::ios::in|std::ios::binary);
    inputFile.fileName(inputFilePath);

    std::string cipherPath = createCipherFilePath(inputFilePath, cipherFilePath);

    fstreamExtension cipherFile(cipherPath.c_str(), std::ios::out|std::ios::binary);
    cipherFile.fileName(cipherFilePath);

    uint8_t extensionBytes[16];
    std::string extension = extensionFromFileName(fileNameFromPath(inputFilePath));
    stringToBytes(extension, extensionBytes);

    uint8_t input[16], output[16], xorVector[16];

    uint8_t* keySchedule = new uint8_t[16 * (this -> Nr + 1)];

    if(keySchedule != nullptr)
    {
        this -> keyExpansion(key, keySchedule);
        this -> generateInitVector(xorVector);

        for(unsigned short i = 0; i < 16; i++)
            input[i] = AES_CxDecipher::verify[i];

        CBC_Encryption(input, output, xorVector, keySchedule);

        cipherFile.writeBytes(xorVector, 16 * sizeof(uint8_t));
        cipherFile.writeBytes(output, 16 * sizeof(uint8_t));
        cipherFile.writeBytes(extensionBytes, 16 * sizeof(uint8_t));

        unsigned long iterations = inputFile.fileSize() / 16;

        for(unsigned long i = 0; i < iterations; i++)
        {
            inputFile.readBytesLimited(input, 16 * sizeof(uint8_t));
            CBC_Encryption(input, output, xorVector, keySchedule);

            for(unsigned short i = 0; i < 16; i++)
                xorVector[i] = output[i];

            cipherFile.writeBytes(output, 16 * sizeof(uint8_t));
        }

        if(inputFile.fileSize() % 16 != 0)
        {
            inputFile.readBytesLimited(input, 16 * sizeof(uint8_t));
            this -> padBlock(inputFile.fileSize(), input);
            CBC_Encryption(input, output, xorVector, keySchedule);
            cipherFile.writeBytes(output, 16 * sizeof(uint8_t));
        }
    }
}

int AES_CxDecipher::DecryptFile(const char* cipherFilePath, const char* outputFilePath, const uint8_t* key)
{
    const uint8_t padRecognition = 0x80;
    fstreamExtension inputFile(cipherFilePath, std::ios::in|std::ios::binary);
    inputFile.fileName(cipherFilePath);

    uint8_t input[16], output[16], xorVector[16], extensionBytes[16];

    uint8_t* keySchedule = new uint8_t[16 * (this -> Nr + 1)];
    if(keySchedule != nullptr)
    {
        this -> keyExpansion(key, keySchedule);
        inputFile.readBytesLimited(xorVector, 16 * sizeof(uint8_t));
        inputFile.readBytesLimited(input, 16 * sizeof(uint8_t));
        CBC_Decryption(input, output, xorVector, keySchedule);

        for(unsigned short i = 0; i < 16; i++)
            if(output[i] != AES_CxDecipher::verify[i])
                return 0;

            char garbage = (char)0x00;
            inputFile.readBytesLimited(extensionBytes, 16 * sizeof(uint8_t));
            std::string deciphName = fileNameFromExt(fileNameFromPath(cipherFilePath));
            std::string ext = bytesToString(extensionBytes);
            ext.erase(std::remove(ext.begin(), ext.end(), garbage), ext.end());
            deciphName.append(ext);
            std::string outputFile(outputFilePath);
            outputFile.append("\\");
            outputFile.append(deciphName);

            fstreamExtension decipherFile(outputFile, std::ios::out|std::ios::binary);
            decipherFile.fileName(outputFile);

            unsigned long iterations = inputFile.fileSize() / 16;

            for(unsigned long i = 0; i < iterations - 3; i++)
            {
                if(i == iterations - 4)
                {
                    inputFile.readBytesLimited(input, 16 * sizeof(uint8_t));
                    CBC_Decryption(input, output, xorVector, keySchedule);

                    for(unsigned short j = 0; j < 16; j++)
                    {
                        if(output[j] != 0x80)
                            decipherFile.writeBytes(&output[j], sizeof(uint8_t));
                        else
                            break;
                    }
                    break;
                }

                inputFile.readBytesLimited(input, 16 * sizeof(uint8_t));
                CBC_Decryption(input, output, xorVector, keySchedule);

                for(unsigned short i = 0; i < 16; i++)
                    xorVector[i] = input[i];

                decipherFile.writeBytes(output, 16 * sizeof(uint8_t));
            }
    }

    return 1;
}

void AES_CxDecipher::keyExpansion(const uint8_t* key, uint8_t* keySchedule)
{
    uint8_t temp[4];
    unsigned i = 0;

    for(; i < this -> Nk; i++)
    {
        for(unsigned short j = 0; j < 4; j++)
        {
            keySchedule[4 * i + j] = key[4 * i + j];
        }
    }

    i = this -> Nk;

    while(i < (4 * (this -> Nr + 1)))
    {
        for(unsigned short j = 0; j < 4; j++)
        {
            temp[j] = keySchedule[4 * (i - 1) + j];
        }

        if(i % this -> Nk == 0)
        {
            for(unsigned short j = 0; j < 3; j++) ///RotWord SubRoutine/
            {
                std::swap(temp[j], temp[j + 1]);
            }

            for(unsigned short j = 0; j < 4; j++) ///SubWord SubRoutine/
            {
                temp[j] = get_SBOX_value(temp[j]);
            }

            for(unsigned short j = 0; j < 4; j++)
            {
                if(j == 0)
                    temp[j] ^= R_CON[(i / this -> Nk) - 1];

                else
                    temp[j] ^= 0x00;
            }

        }

        else if((this -> Nk > 6) && (i % this -> Nk == 4))
        {
            for(unsigned short j = 0; j < 4; j++) ///SubWord SubRoutine/
            {
                temp[j] = get_SBOX_value(temp[j]);
            }
        }

        for(unsigned short j = 0; j < 4; j++)
        {
            keySchedule[(4 * i) + j] = keySchedule[(4 * (i - this -> Nk)) + j] ^ temp[j];
        }

        i += 1;
    }
}

void AES_CxDecipher::addRoundKey(uint8_t state[4][4], uint8_t* keySchedule, int round)
{
    for(unsigned short i = 0; i < 4; i++)
        for(unsigned short j = 0; j < 4; j++)
        {
            state[j][i] ^= keySchedule[4 * (round * 4 + i) + j];
        }
}


///CIPHER SUBROUTINES/

uint8_t AES_CxDecipher::get_SBOX_value(uint8_t byte)    ///static
        {
            return(S_BOX[byte]);
        }

void AES_CxDecipher::subBytes(uint8_t state[4][4])
    {
        for(unsigned short i = 0; i < 4; i++)
        {
            for(unsigned short j = 0; j < 4; j++)
            {
                state[i][j] = AES_CxDecipher::get_SBOX_value(state [i][j]);
            }
        }
    }

void AES_CxDecipher::shiftRows(uint8_t state[4][4])
{
    ///no shift row is to be applied on row 0/

    ///shift row operation on row 1/
    for(unsigned short i = 0; i < 3; i++)
    {
        std::swap (state[1][i], state[1][i + 1]);
    }

    ///shift row operation on row 2/
    for(unsigned short i = 0; i < 2; i++)
    {
        for(unsigned short j = 0; j < 3; j++)
        {
            std::swap(state[2][j], state[2][j + 1]);
        }
    }

    ///shift row operation on row 3/
    for(unsigned short i = 0; i < 3; i++)
    {
        for(unsigned short j = 0; j < 3; j++)
        {
            std::swap(state[3][j], state[3][j + 1]);
        }
    }
}

void AES_CxDecipher::mixColumns(uint8_t state[4][4])
{
    uint8_t temp [4];

    for(unsigned short i = 0; i < 4; i++)
    {
        for(unsigned short j = 0; j < 4; j++)
        {
            temp[j]=state[j][i];
        }

        temp [0] = byteProduct(0x02 ,state[0][i]) ^ byteProduct(0x03, state[1][i]) ^ state[2][i] ^ state[3][i];
        temp [1] = state[0][i] ^ byteProduct(0x02, state[1][i]) ^ byteProduct(0x03, state[2][i]) ^ state[3][i];
        temp [2] = state[0][i] ^ state[1][i] ^ byteProduct(0x02, state[2][i]) ^ byteProduct(0x03, state[3][i]);
        temp [3] = byteProduct(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ byteProduct(0x02, state[3][i]);

        for(unsigned short j = 0; j < 4; j++)
        {
            state[j][i] = temp[j];
        }
    }
}


///DECIPHER SUBROUTINES/

uint8_t AES_CxDecipher::get_invSBOX_value(uint8_t byte)    ///static
{
            return(invS_BOX[byte]);
}

void AES_CxDecipher::invSubBytes(uint8_t inv_state[4][4])
{
        for(unsigned short i = 0; i < 4; i++)
        {
            for(unsigned short j = 0; j < 4; j++)
            {
                inv_state[i][j] = AES_CxDecipher::get_invSBOX_value(inv_state [i][j]);
            }
        }
}

void AES_CxDecipher::invShiftRows(uint8_t inv_state[4][4])
{
    ///no inverse shift row is to be applied on row 0/

    ///inverse shift row operation on row 1/
    for(unsigned short i = 3; i > 0; i--)
        std::swap(inv_state[1][i], inv_state[1][i - 1]);

    ///inverse shift row operation on row 2/
    for(unsigned short i = 0; i < 2; i++)
    {
        for(unsigned short j = 3; j > 0; j--)
        {
            std::swap(inv_state[2][j], inv_state[2][j - 1]);
        }
    }

    ///inverse shift row operation on row 3/
    for(unsigned short i = 0; i < 3; i++)
    {
        for(unsigned short j = 3; j > 0; j--)
        {
            std::swap(inv_state[3][j], inv_state[3][j - 1]);
        }
    }
}

void AES_CxDecipher::invMixColumns(uint8_t inv_state[4][4])
{
    uint8_t res[4];

    for(unsigned short i = 0; i < 4; i++)
    {
        for(unsigned short j = 0; j < 4; j++)
        {
            res[j]= inv_state[j][i];
        }

        res[0] = (((byteProduct(inv_state[0][i],0x0e) ^ byteProduct(inv_state[1][i],0x0b)) ^ byteProduct(inv_state[2][i],0x0d)) ^ byteProduct(inv_state[3][i],0x09));
        res[1] = (((byteProduct(inv_state[0][i],0x09) ^ byteProduct(inv_state[1][i],0x0e)) ^ byteProduct(inv_state[2][i],0x0b)) ^ byteProduct(inv_state[3][i],0x0d));
        res[2] = (((byteProduct(inv_state[0][i],0x0d) ^ byteProduct(inv_state[1][i],0x09)) ^ byteProduct(inv_state[2][i],0x0e)) ^ byteProduct(inv_state[3][i],0x0b));
        res[3] = (((byteProduct(inv_state[0][i],0x0b) ^ byteProduct(inv_state[1][i],0x0d)) ^ byteProduct(inv_state[2][i],0x09)) ^ byteProduct(inv_state[3][i],0x0e));

        for(unsigned short j = 0; j < 4; j++)
        {
            inv_state[j][i] = res[j];
        }
    }
}

///BLOCK CIPHER MODE SUBROUTINES/
void AES_CxDecipher::padBlock(unsigned long long fileSize, uint8_t* inputBlock)
{
    unsigned short padInitPos = static_cast<unsigned short> (fileSize % 16);
    inputBlock[padInitPos] = 0x80;

    for(padInitPos += 1; padInitPos < 16; padInitPos++)
    {
        inputBlock[padInitPos] = 0x00;
    }
}

template<std::size_t N>
void AES_CxDecipher::generateInitVector(uint8_t (&IV_buff)[N])
{
    using bytes_randomizer = std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t>;
    std::default_random_engine rd;
    bytes_randomizer bytes(rd);

    std::generate(std::begin(IV_buff), std::end(IV_buff), std::ref(bytes));
}

///CIPHER/DECIPHER ROUNTINES/
void AES_CxDecipher::AES_CIPHER(uint8_t plainText[16], uint8_t cipherText[16], uint8_t keySchedule[])
{
    uint8_t state[4][4];

    /// state = plainText /
    for(unsigned short r = 0; r < 4; r++)
        for(unsigned short c = 0; c < 4; c++)
        {
            state [r][c] = plainText [r + 4 * c];
        }

    this -> addRoundKey(state, keySchedule, 0);

    for(unsigned short round = 1; round <= this -> Nr - 1; round++)
    {
        this -> subBytes(state);
        this -> shiftRows(state);
        this -> mixColumns(state);
        this -> addRoundKey(state, keySchedule, round);
    }

    this -> subBytes(state);
    this -> shiftRows(state);
    this -> addRoundKey(state, keySchedule, this -> Nr);

    /// cipherText = state /
    for(unsigned short r = 0; r < 4; r++)
        for(unsigned short c = 0; c < 4; c++)
        {
            cipherText [r + 4 * c] = state [r][c];
        }
}

void AES_CxDecipher::AES_INVERSE_CIPHER(uint8_t cipherText[16], uint8_t plainText[16], uint8_t keySchedule[])
{
    uint8_t state[4][4];

    /// state = cipherText /
    for(unsigned short r = 0; r < 4; r++)
        for(unsigned short c = 0; c < 4; c++)
        {
            state [r][c] = cipherText [r + 4 * c];
        }

    this -> addRoundKey(state, keySchedule, this -> Nr);

    for(unsigned short round = this -> Nr - 1; round >= 1; round--)
    {
        this -> invShiftRows(state);
        this -> invSubBytes(state);
        this -> addRoundKey(state, keySchedule, round);
        this -> invMixColumns(state);
    }

    this -> invShiftRows(state);
    this -> invSubBytes(state);
    this -> addRoundKey(state, keySchedule, 0);

    /// plainText = state/
    for(unsigned short r = 0; r < 4; r++)
        for(unsigned short c = 0; c < 4; c++)
        {
            plainText [r + 4 * c] = state [r][c];
        }
}

///BLOCK CIPHER OPERATION MODE ROUTINES/

    ///CBC MODE ROUTINES/
void AES_CxDecipher::CBC_Encryption(uint8_t plainText[16], uint8_t outputCipherText[16], uint8_t xorVector[16], uint8_t* keySchedule)
{
    for(unsigned short i = 0; i < 16; i++)
            plainText[i] ^= xorVector[i];

    AES_CIPHER(plainText, outputCipherText, keySchedule);
}

void AES_CxDecipher::CBC_Decryption(uint8_t cipherText[16], uint8_t outputPlainText[16],uint8_t xorVector[16], uint8_t* keySchedule)
{
    AES_INVERSE_CIPHER(cipherText, outputPlainText, keySchedule);

    for(unsigned short i = 0; i < 16; i++)
        outputPlainText[i] ^= xorVector[i];
}

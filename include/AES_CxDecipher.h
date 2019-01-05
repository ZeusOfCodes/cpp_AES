#ifndef AES_CXDECIPHER_H
#define AES_CXDECIPHER_H

class AES_CxDecipher
{
    ///DATA MEMBERS FOR CIPHER/DECIPHER ROUTINES/
    private:

        static const uint8_t S_BOX[256];
        static const uint8_t invS_BOX[256];
        static const uint8_t R_CON[11];
        static const uint8_t verify[16];

        unsigned short Nr;
        unsigned short Nk;

    public:
///WRAPPER ROUTINES/
        void EncryptFile(const char*, const char*, const uint8_t*);
        int DecryptFile(const char*, const char*, const uint8_t*);


///ROUTINES FOR AES OPERATION IN CBC MODE/
        void CBC_Encryption(uint8_t*, uint8_t*, uint8_t*, uint8_t*);
        void CBC_Decryption(uint8_t*, uint8_t*, uint8_t*, uint8_t*);

///ROUTINES FOR AES OPERATION IN CTR MODE/
///        void CTR_Encryption(const char*, uint8_t*);
///        void CTR_Decryption(const char*, uint8_t*);

    public:
    ///CLASS CONSTRUCTOR/
        AES_CxDecipher(const uint8_t);

///DATA MEMBERS FOR ALGORITHM SPECIFICATION/

    ///CONST DATA MEMBERS FOR AES MODE PF OPERATION/

        static const uint8_t AES128 = 0x80;
        static const uint8_t AES192 = 0xc0;
        static const uint8_t AES256 = 0x10;

    private:

///COMMON ROUTINES FOR CIPHER AND DECIPHER/
        static inline uint8_t byteProduct(uint8_t x, uint8_t y) ///returns product for GF(2^8).
        {
            uint8_t result = 0, temp;

            while(x != 0)
            {
                if((x & 1) != 0)
                    result ^= y;

                temp = y & 0x80;
                y <<= 1;

                if(temp != 0)
                    y ^= 0x1b;

                x >>= 1;
            }

            return result;
        }

        void keyExpansion(const uint8_t*, uint8_t*);
        void addRoundKey(uint8_t [4][4], uint8_t*, int);

///CIPHER SUBROUTINES/
        static uint8_t get_SBOX_value(uint8_t);
        void subBytes(uint8_t [4][4]);
        void shiftRows(uint8_t [4][4]);
        void mixColumns(uint8_t [4][4]);


///DECIPHER SUBROUTINES/
        static uint8_t get_invSBOX_value(uint8_t);
        void invSubBytes(uint8_t [4][4]);
        void invShiftRows(uint8_t [4][4]);
        void invMixColumns(uint8_t [4][4]);

///CIPHER/DECIPHER ROUTINES/
        void AES_CIPHER(uint8_t*, uint8_t*, uint8_t*);
        void AES_INVERSE_CIPHER(uint8_t*, uint8_t*, uint8_t*);

///BLOCK CIPHER MODE OF OPERATION SUBROUTINES/
        void padBlock(unsigned long long, uint8_t*);
        template<std::size_t N>
        void generateInitVector(uint8_t (&IV_buff)[N]);
};

#endif // AES_CXDECIPHER_H

#include <iostream>
#include <fstream>
#include <string>
#include "fstreamExtension.h"

bool fstreamExtension::copyFile (const std::string& __copyFile)
{
    uint8_t fByte;
    int __end_of_file;
    std::fstream copyStream(__copyFile.c_str(), std::ios::out|std::ios::trunc|std::ios::binary);

    if(!copyStream)
        return false;
    else
    {
        while(1)
        {
            this -> read (reinterpret_cast<char*> (&fByte), sizeof (uint8_t));
            copyStream.write (reinterpret_cast<char*> (&fByte), sizeof (uint8_t));

            if((__end_of_file = this -> peek()) == EOF)
                break;
        }
        return true;
    }
}

void fstreamExtension::readBytes (uint8_t* byteBuff)
{
    this -> read (reinterpret_cast<char*> (byteBuff), this -> fstreamExtension::fileSize());
//        if((__end_of_file = this -> peek ()) == EOF)
}

void fstreamExtension::readBytesLimited (uint8_t* byteBuff, long long int streamSize)
{
    this -> read (reinterpret_cast<char*> (byteBuff), streamSize);
}
/*
void fstreamExtension::readBytesMultiThreaded (std::vector<char>& vBuff)
{
    long long int threadBytes [4] = {0, 0, 0, 0};

    if(this -> fileSize() % 2 == 0)
    {
        threadBytes[0] = this -> fileSize() / 2;

        if(threadBytes[0] % 2 == 0)
        {
            threadBytes[0] /= 2;
            threadBytes[1] = threadBytes[0];
            threadBytes[2] = threadBytes[0];
            threadBytes[3] = threadBytes[0];
        }

        else
        {
            threadBytes[0] = (threadBytes[0] - 1) / 2;
            threadBytes[1] = threadBytes[0] + 1;
            threadBytes[2] = threadBytes[0];
            threadBytes[3] = threadBytes[1];
        }

    }

    else
    {
        threadBytes[0] = (this -> fileSize() - 1) / 2;

        if(threadBytes[0] % 2 == 0)
        {
            threadBytes[0] /= 2;
            threadBytes[1] = threadBytes[0];
            threadBytes[2] = threadBytes[0];
            threadBytes[3] = threadBytes[0] + 1;
        }

        else
        {
            threadBytes[0] = (threadBytes[0] - 1) / 2;
            threadBytes[1] = threadBytes[0] + 1;
            threadBytes[2] = threadBytes[0] + 1;
            threadBytes[3] = threadBytes[0] + 1;
        }
    }
}*/

void fstreamExtension::appendByte(uint8_t byte)
{
    this -> write(reinterpret_cast<char*> (&byte), sizeof(uint8_t));
}

void fstreamExtension::writeBytes (uint8_t* byteBuff, long long int streamSize)
{
    this -> write(reinterpret_cast<char*> (byteBuff), streamSize);
}

fstreamExtension::~fstreamExtension()
{
    std::fstream::close();
}

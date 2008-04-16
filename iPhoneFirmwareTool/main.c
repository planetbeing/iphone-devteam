#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <png.h>
#include "main.h"
#include "compression.h"

// put real 837 key here
const unsigned char key837[ AES_BLOCK_SIZE ] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int main(int argc, char *argv[])
{
    h8900 header8900;
    f8900 footer8900;
    hImg2 headerImg2;
    hBootIm headerBootIm;
    hKernel headerKernel;
    int extract, flags, ret;

    printf("iPhone Firmware Tool 1.1 by wizdaz (c) 2008\n\n");

    if (argc != 4 && argc != 3)
    {
        printf("Usage\n");
        printf("Extract file: ft <8900file> <outputfile>\n");
        printf(" Inject file: ft <8900file> <newfile> <outputfile>\n");

        return 1;
    }

    extract = (argc == 3);

    ret = parse8900(argv[1], &header8900, &footer8900, &headerKernel, &headerImg2, &headerBootIm, &flags, extract, argv[2]);

    if(extract == 0)
    {
        if((flags & IsKernelFile) == IsKernelFile)
            ret = doKernelFile(argv[2], &header8900, &footer8900, &headerKernel, argv[3]);
        else if((flags & IsPlainFile) == IsPlainFile)
            ret = doPlainFile(argv[2], &header8900, &footer8900, argv[3]);
        else if((flags & IsImg2File) == IsImg2File)
        {
            if((flags & IsBootImFile) == IsBootImFile)
                ret = doBootImFile(argv[2], &header8900, &footer8900, &headerImg2, &headerBootIm, argv[3]);
            else
                ret = doImg2File(argv[2], &header8900, &footer8900, &headerImg2, argv[3]);
        }
    }

    return ret;
}

int parse8900(const char* filename, h8900* pHeader8900, f8900* pFooter8900, hKernel* pHeaderKernel, hImg2* pHeaderImg2, hBootIm* pHeaderBootIm, int* pFlags, int extract, const char* output)
{
    AES_KEY ectx;
    unsigned char zero_iv[ AES_BLOCK_SIZE ] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    FILE *in;
    unsigned char *inbuf, *p;
    unsigned int size;
    int ret = 0;

    *pFlags = 0;

    in = fopen(filename, "rb");
    if(!in)
    {
        fprintf(stderr, "ERR: Could not open '%s' for reading.\n", filename);
        return -1;
    }

    fseek(in, 0, SEEK_END);
    size = ftell(in);
    rewind(in);

    printf("... Begin parsing 8900 file.\n");

    if(size < sizeof(h8900) + sizeof(f8900))
    {
        fprintf(stderr, "ERR: Incorrect 8900 file '%s'. Filesize is less than should be.\n", filename);
        fclose(in);
        return -1;
    }

    inbuf = (unsigned char *)malloc(sizeof(char) * size);
    fread(inbuf, 1, size, in);
    fclose(in);

    p = inbuf;
    memcpy(pHeader8900, p, sizeof(h8900));

    p += sizeof(h8900);
    memcpy(pFooter8900, p + pHeader8900->sigOffset, sizeof(f8900));
    
    if(pHeader8900->magic != endian_swap('8900'))
    {
        fprintf(stderr, "ERR: Incorrect 8900 file '%s'. Wrong magic value.\n", filename);
        free(inbuf);
        return -1;
    }

    size = pHeader8900->dataSize;
    if(pHeader8900->encrypted == Encrypted8900)
    {
        printf("... Decrypting 8900 data.\n");
        AES_set_decrypt_key( key837, 128, &ectx );
        AES_cbc_encrypt( p, p, size, &ectx, zero_iv, AES_DECRYPT );
    }

    if(size < sizeof(hKernel))
    {
        fprintf(stderr, "ERR: Incorrect 8900 file '%s'. Filesize is less than should be.\n", filename);
        free(inbuf);
        return -1;
    }

    memcpy(pHeaderKernel, p, sizeof(hKernel));
    if(pHeaderKernel->magic == endian_swap('comp'))
    {
        *pFlags |= IsKernelFile;

        p += sizeof(hKernel);
        size = endian_swap(pHeaderKernel->compressed_size);

        printf("... KernelCache file found.\n");
    }
    else
    {
        if(size < sizeof(hImg2))
        {
            fprintf(stderr, "ERR: Incorrect 8900 file '%s'. Filesize is less than should be.\n", filename);
            free(inbuf);
            return -1;
        }

        memcpy(pHeaderImg2, p, sizeof(hImg2));
        if(pHeaderImg2->magic == 'Img2')
        {
            *pFlags |= IsImg2File;

            p += sizeof(hImg2);
            size = pHeaderImg2->dataLen;

            printf("... Img2 file found.\n");

            if(size > sizeof(hBootIm))
            {
                memcpy(pHeaderBootIm, p, sizeof(hBootIm));
                if(strcmp(pHeaderBootIm->magic,"iBootIm") == 0)
                {
                    *pFlags |= IsBootImFile;

                    p += sizeof(hBootIm);
                    size -= sizeof(hBootIm);

                    printf("... iBootIm file found.\n");
                }
            }
        }
        else
        {
            *pFlags |= IsPlainFile;

            printf("... Plain file found.\n");
        }
    }

    if(extract)
        ret = extractFile(p, size, pHeaderKernel, pHeaderImg2, pHeaderBootIm, pFlags, output);

    free(inbuf);

    return ret;
}

int extractFile(unsigned char* p, unsigned int size, hKernel* pHeaderKernel, hImg2* pHeaderImg2, hBootIm* pHeaderBootIm, int* pFlags, const char* filename)
{
    FILE *out;
    unsigned char *outbuf;
    unsigned int imSize;

    out = fopen(filename, "wb");
    if(!out)
    {
        fprintf(stderr, "ERR: Could not open '%s' for writing.\n", filename);
        return -1;
    }

    if((*pFlags & IsKernelFile) == IsKernelFile)
    {
        printf("... Decompressing KernelCache file.\n");

        outbuf = (unsigned char *)malloc(endian_swap(pHeaderKernel->uncompressed_size));
        memset(outbuf, 0, endian_swap(pHeaderKernel->uncompressed_size));
        size = decompress_lzss(outbuf, p, size);

        if(size != endian_swap(pHeaderKernel->uncompressed_size))
        {
            fprintf(stderr, "ERR: Incorrect un-compressed kernel cache size: %d != %d.\n", size, endian_swap(pHeaderKernel->uncompressed_size));
            free(outbuf);
            return -1;
        }
    }
    else if((*pFlags & IsImg2File) == IsImg2File)
    {
        if((*pFlags & IsBootImFile) == IsBootImFile)
        {
            imSize = pHeaderBootIm->width * pHeaderBootIm->height;

            if(pHeaderBootIm->type == 'argb')
                imSize *= 4;
            else if(pHeaderBootIm->type == 'grey')
                imSize *= 2;
            else
            {
                fprintf(stderr, "ERR: Unknown iBootIm file type: %08X.\n", pHeaderBootIm->type);
                return -1;
            }

            printf("... Decompressing iBootIm file.\n");

            outbuf = (unsigned char *)malloc(imSize);
            memset(outbuf, 0, imSize);
            size = decompress_lzss(outbuf, p, size);

            if(size != imSize)
            {
                fprintf(stderr, "ERR: Incorrect un-compressed iBootIm file size: %d != %d.\n", size, imSize);
                free(outbuf);
                return -1;
            }
        }
        else
        {
            outbuf = (unsigned char *)malloc(size);
            memcpy(outbuf, p, size);
        }
    }
    else // Plain file
    {
        outbuf = (unsigned char *)malloc(size);
        memcpy(outbuf, p, size);
    }

    printf("... Writing extracted file.\n");

    fwrite(outbuf, 1, size, out);
    free(outbuf);
    fclose(out);

    return 0;
}

int doKernelFile(const char* filename, h8900* pHeader8900, f8900* pFooter8900, hKernel* pHeaderKernel, const char* output)
{
    AES_KEY ectx;
    unsigned char zero_iv[ AES_BLOCK_SIZE ] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    FILE *in, *out;
    unsigned char *inbuf, *outbuf, *end;
    unsigned int size;

    in = fopen(filename, "rb");
    if(!in)
    {
        fprintf(stderr, "ERR: Could not open '%s' for reading.\n", filename);
        return -1;
    }

    out = fopen(output, "wb");
    if(!out)
    {
        fprintf(stderr, "ERR: Could not open '%s' for writing.\n", filename);
        fclose(in);
        return -1;
    }

    fseek(in, 0, SEEK_END);
    size = ftell(in);
    rewind(in);

    printf("... Begin injecting new file.\n");
    
    inbuf = (unsigned char *)malloc(size);
    fread(inbuf, 1, size, in);
    fclose(in);

    pHeaderKernel->adler32 = endian_swap(local_adler32(inbuf, size));
    pHeaderKernel->uncompressed_size = endian_swap(size);

    printf("... Compressing KernelCache file.\n");

    end = compress_lzss(inbuf, size, inbuf, size);
    size = (unsigned int)(end - inbuf);
    pHeaderKernel->compressed_size = endian_swap(size); 

    pHeader8900->dataSize = sizeof(hKernel) + size;
    pHeader8900->dataSize = (pHeader8900->dataSize % AES_BLOCK_SIZE == 0) ? pHeader8900->dataSize : ((pHeader8900->dataSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    pHeader8900->sigOffset = pHeader8900->dataSize;
    pHeader8900->certOffset = pHeader8900->sigOffset + 0x80;

    outbuf = (unsigned char *)malloc(pHeader8900->dataSize);
    memset(outbuf, 0, pHeader8900->dataSize);
    memcpy(outbuf, pHeaderKernel, sizeof(hKernel));
    memcpy(outbuf + sizeof(hKernel), inbuf, size);
    free(inbuf);

    if(pHeader8900->encrypted == Encrypted8900)
    {
        printf("... Encrypting 8900 data.\n");
        AES_set_encrypt_key( key837, 128, &ectx );
        AES_cbc_encrypt( outbuf, outbuf, pHeader8900->dataSize, &ectx, zero_iv, AES_ENCRYPT );
    }

    resignHeader8900(pHeader8900);
    fwrite(pHeader8900, 1, sizeof(h8900), out);
    fwrite(outbuf, 1, pHeader8900->dataSize, out);
    fwrite(pFooter8900, 1, sizeof(f8900), out);

    free(outbuf);
    fclose(out);

    printf("... KernelCache file injected.\n");

    return 0;
}

int doPlainFile(const char* filename, h8900* pHeader8900, f8900* pFooter8900, const char* output)
{
    AES_KEY ectx;
    unsigned char zero_iv[ AES_BLOCK_SIZE ] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    FILE *in, *out;
    unsigned char *inbuf, *outbuf;
    unsigned int size;

    in = fopen(filename, "rb");
    if(!in)
    {
        fprintf(stderr, "ERR: Could not open '%s' for reading.\n", filename);
        return -1;
    }

    out = fopen(output, "wb");
    if(!out)
    {
        fprintf(stderr, "ERR: Could not open '%s' for writing.\n", filename);
        fclose(in);
        return -1;
    }

    fseek(in, 0, SEEK_END);
    size = ftell(in);
    rewind(in);

    printf("... Begin injecting new file.\n");
    
    inbuf = (unsigned char *)malloc(size);
    fread(inbuf, 1, size, in);
    fclose(in);

    pHeader8900->dataSize = size;
    pHeader8900->dataSize = (pHeader8900->dataSize % AES_BLOCK_SIZE == 0) ? pHeader8900->dataSize : ((pHeader8900->dataSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    pHeader8900->sigOffset = pHeader8900->dataSize;
    pHeader8900->certOffset = pHeader8900->sigOffset + 0x80;

    outbuf = (unsigned char *)malloc(pHeader8900->dataSize);
    memset(outbuf, 0, pHeader8900->dataSize);
    memcpy(outbuf, inbuf, size);
    free(inbuf);

    if(pHeader8900->encrypted == Encrypted8900)
    {
        printf("... Encrypting 8900 data.\n");
        AES_set_encrypt_key( key837, 128, &ectx );
        AES_cbc_encrypt( outbuf, outbuf, pHeader8900->dataSize, &ectx, zero_iv, AES_ENCRYPT );
    }

    resignHeader8900(pHeader8900);
    fwrite(pHeader8900, 1, sizeof(h8900), out);
    fwrite(outbuf, 1, pHeader8900->dataSize, out);
    fwrite(pFooter8900, 1, sizeof(f8900), out);

    free(outbuf);
    fclose(out);

    printf("... Plain file injected.\n");

    return 0;
}

int doImg2File(const char* filename, h8900* pHeader8900, f8900* pFooter8900, hImg2* pHeaderImg2, const char* output)
{
    AES_KEY ectx;
    unsigned char zero_iv[ AES_BLOCK_SIZE ] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    FILE *in, *out;
    unsigned char *inbuf, *outbuf;
    unsigned int size;

    in = fopen(filename, "rb");
    if(!in)
    {
        fprintf(stderr, "ERR: Could not open '%s' for reading.\n", filename);
        return -1;
    }

    out = fopen(output, "wb");
    if(!out)
    {
        fprintf(stderr, "ERR: Could not open '%s' for writing.\n", filename);
        fclose(in);
        return -1;
    }

    fseek(in, 0, SEEK_END);
    size = ftell(in);
    rewind(in);

    printf("... Begin injecting new file.\n");
    
    inbuf = (unsigned char *)malloc(size);
    fread(inbuf, 1, size, in);
    fclose(in);

    pHeaderImg2->dataLen = size;
    if(pHeader8900->encrypted == Encrypted8900)
        pHeaderImg2->dataLenPadded = (pHeaderImg2->dataLen % AES_BLOCK_SIZE == 0) ? pHeaderImg2->dataLen : ((pHeaderImg2->dataLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    else
        pHeaderImg2->dataLenPadded = pHeaderImg2->dataLen;

    pHeaderImg2->crc = crc32(crc32(0, 0, 0), (unsigned char*)pHeaderImg2, 100);

    pHeader8900->dataSize = sizeof(hImg2) + pHeaderImg2->dataLenPadded;
    pHeader8900->dataSize = (pHeader8900->dataSize % AES_BLOCK_SIZE == 0) ? pHeader8900->dataSize : ((pHeader8900->dataSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    pHeader8900->sigOffset = pHeader8900->dataSize;
    pHeader8900->certOffset = pHeader8900->sigOffset + 0x80;

    outbuf = (unsigned char *)malloc(pHeader8900->dataSize);
    memset(outbuf, 0, pHeader8900->dataSize);
    memcpy(outbuf, pHeaderImg2, sizeof(hImg2));
    memcpy(outbuf + sizeof(hImg2), inbuf, pHeaderImg2->dataLen);
	free(inbuf);
	
    if(pHeader8900->encrypted == Encrypted8900)
    {
        printf("... Encrypting 8900 data.\n");
        AES_set_encrypt_key( key837, 128, &ectx );
        AES_cbc_encrypt( outbuf, outbuf, pHeader8900->dataSize, &ectx, zero_iv, AES_ENCRYPT );
    }

    resignHeader8900(pHeader8900);
    fwrite(pHeader8900, 1, sizeof(h8900), out);
    fwrite(outbuf, 1, pHeader8900->dataSize, out);
    fwrite(pFooter8900, 1, sizeof(f8900), out);

    free(outbuf);
    fclose(out);

    printf("... Img2 file injected.\n");

    return 0;
}

int doBootImFile(const char* filename, h8900* pHeader8900, f8900* pFooter8900, hImg2* pHeaderImg2, hBootIm* pHeaderBootIm, const char* output)
{
    AES_KEY ectx;
    unsigned char zero_iv[ AES_BLOCK_SIZE ] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    FILE *in, *out;
    unsigned char *inbuf, *outbuf, *end;
    unsigned int size, width, height, gray;

    in = fopen(filename, "rb");
    if(!in)
    {
        fprintf(stderr, "ERR: Could not open '%s' for reading.\n", filename);
        return -1;
    }

    printf("... Begin injecting new file.\n");
    printf("... Converting PNG to iBootIm file.\n");

    inbuf = read_png(in, &width, &height, &gray);
    fclose(in);

    if(inbuf == 0)
    {  // Invalid PNG data
        printf("... Invalid PNG data, assuming raw data.\n");
    }
    
    out = fopen(output, "wb");
    if(!out)
    {
        fprintf(stderr, "ERR: Could not open '%s' for writing.\n", filename);
        free(inbuf);
        return -1;
    }

    if(gray)
    {
        pHeaderBootIm->type = 'grey';
        size = width * height * 2;
    }
    else
    {
        pHeaderBootIm->type = 'argb';
        size = width * height * 4;
    }

    pHeaderBootIm->width = width;
    pHeaderBootIm->height = height;

    printf("... Compressing iBootIm file.\n");

    end = compress_lzss(inbuf, size, inbuf, size);
    size = (unsigned int)(end - inbuf);

    pHeaderImg2->dataLen = sizeof(hBootIm) + size;
    if(pHeader8900->encrypted == Encrypted8900)
        pHeaderImg2->dataLenPadded = (pHeaderImg2->dataLen % AES_BLOCK_SIZE == 0) ? pHeaderImg2->dataLen : ((pHeaderImg2->dataLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    else
        pHeaderImg2->dataLenPadded = pHeaderImg2->dataLen;

    pHeaderImg2->crc = crc32(crc32(0, 0, 0), (unsigned char*)pHeaderImg2, 100);

    pHeader8900->dataSize = sizeof(hImg2) + pHeaderImg2->dataLenPadded;
    pHeader8900->dataSize = (pHeader8900->dataSize % AES_BLOCK_SIZE == 0) ? pHeader8900->dataSize : ((pHeader8900->dataSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    pHeader8900->sigOffset = pHeader8900->dataSize;
    pHeader8900->certOffset = pHeader8900->sigOffset + 0x80;

    outbuf = (unsigned char *)malloc(pHeader8900->dataSize);
    memset(outbuf, 0, pHeader8900->dataSize);
    memcpy(outbuf, pHeaderImg2, sizeof(hImg2));
    memcpy(outbuf + sizeof(hImg2), pHeaderBootIm, sizeof(hBootIm));
    memcpy(outbuf + sizeof(hImg2) + sizeof(hBootIm), inbuf, size);
	free(inbuf);
	
    if(pHeader8900->encrypted == Encrypted8900)
    {
        printf("... Encrypting 8900 data.\n");
        AES_set_encrypt_key( key837, 128, &ectx );
        AES_cbc_encrypt( outbuf, outbuf, pHeader8900->dataSize, &ectx, zero_iv, AES_ENCRYPT );
    }

    resignHeader8900(pHeader8900);
    fwrite(pHeader8900, 1, sizeof(h8900), out);
    fwrite(outbuf, 1, pHeader8900->dataSize, out);
    fwrite(pFooter8900, 1, sizeof(f8900), out);

    free(outbuf);
    fclose(out);

    printf("... iBootIm file injected.\n");

    return 0;
}

unsigned char* read_png(FILE *fp, unsigned int *width, unsigned int *height, unsigned int *gray)
{
	char *imageData = NULL;
	png_structp png_ptr;
	png_infop info_ptr;
	unsigned int row, i;
	unsigned int p = 0;

	png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	info_ptr = png_create_info_struct(png_ptr);
	png_init_io(png_ptr, fp);
	png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

	if(png_ptr->color_type == PNG_COLOR_TYPE_RGB_ALPHA)
	{
		imageData = (char*)malloc(png_ptr->rowbytes * png_ptr->height);
		for (row = 0; row < png_ptr->height; row++)
		{
			for (i = 0; i < png_ptr->rowbytes; i = i + 4)
			{
				imageData[p++] = (unsigned char)info_ptr->row_pointers[row][i + 2];
				imageData[p++] = (unsigned char)info_ptr->row_pointers[row][i + 1];
				imageData[p++] = (unsigned char)info_ptr->row_pointers[row][i];
				imageData[p++] = 255 - (unsigned char)info_ptr->row_pointers[row][i + 3];
			}
		}

		*width = png_ptr->width;
		*height = png_ptr->height;
        *gray = 0;
	}
    else if(png_ptr->color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
    {
		imageData = (char*)malloc(png_ptr->rowbytes * png_ptr->height);
		for (row = 0; row < png_ptr->height; row++)
		{
			for (i = 0; i < png_ptr->rowbytes; i = i + 2)
			{
				imageData[p++] = (unsigned char)info_ptr->row_pointers[row][i];
				imageData[p++] = 255 - (unsigned char)info_ptr->row_pointers[row][i + 1];
			}
		}
        
        *width = png_ptr->width;
		*height = png_ptr->height;
        *gray = 1;
    }

	png_destroy_read_struct(&png_ptr, &info_ptr, 0);

	return imageData;
}

void resignHeader8900(h8900* pHeader8900)
{
    AES_KEY ectx;
    SHA_CTX sctx;
    unsigned char zero_iv[AES_BLOCK_SIZE] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    unsigned char md[SHA_DIGEST_LENGTH] = {0};

    SHA1_Init(&sctx);
    SHA1_Update(&sctx,pHeader8900,0x40);
    SHA1_Final(&(md[0]),&sctx);

    AES_set_encrypt_key( key837, 128, &ectx );
    AES_cbc_encrypt( md, pHeader8900->sig2, AES_BLOCK_SIZE, &ectx, zero_iv, AES_ENCRYPT );
}

unsigned int endian_swap(unsigned int x)
{
    x = (x>>24) | 
        ((x<<8) & 0x00FF0000) |
        ((x>>8) & 0x0000FF00) |
        (x<<24);

    return x;
}
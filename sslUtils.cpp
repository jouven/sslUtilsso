#include "sslUtils.hpp"
namespace eines
{
//bool sslUtils_c::RSAGenerated_f() const
//{
//    return RSAGenerated_pri;
//}

//bool sslUtils_c::keyGenerated_f() const
//{
//    return keyGenerated_pri;
//}

//bool sslUtils_c::certficateGenerated_f() const
//{
//    return certficateGenerated_pri;
//}

void sslUtils_c::freeOpensslStuff_f()
{
    if (certficateGenerated_pri)
    {
        X509_free(X509_pri);
    }
    if (keyInitialized_pri)
    {
        EVP_PKEY_free(key_pri);
    }
    //looks like it's not required, did a valgrind + gdb on opensslKeyGenerationTest2 and it didn't complain
//    if (RSA_pri)
//    {
//        RSA_free(RSA_pri);
//    }
    if (bnInitialized_pri)
    {
        BN_free(bn_pri);
    }
}

sslUtils_c::~sslUtils_c()
{
    freeOpensslStuff_f();
}

void sslUtils_c::generateRSA_f()
{
    //setup big number
    bn_pri = BN_new();
    bnInitialized_pri = true;
    int retTmp(BN_set_word(bn_pri, RSA_F4));
    if(retTmp != 1){
        appendError_f("Unable to BN_set_word(bn, RSA_F4).");
        return;
    }

    //Generate the RSA
    RSA_pri = RSA_new();
    RSAInitialized_pri = true;
    retTmp = RSA_generate_key_ex(RSA_pri, 2048, bn_pri, NULL);
    if(retTmp != 1){
        appendError_f("Unable to RSA_generate_key_ex(rsa_glo, 2048, bne_glo, NULL).");
        return;
    }
    RSAGenerated_pri = true;
}

void sslUtils_c::generateKey_f()
{
    if (not RSAGenerated_pri)
    {
        appendError_f("RSA wasn't generated, generate RSA first.");
        return;
    }
    key_pri = EVP_PKEY_new();
    keyInitialized_pri = true;
    if(not key_pri)
    {
       appendError_f("Unable to create EVP_PKEY structure for key.");
       return;
    }

    if(EVP_PKEY_assign_RSA(key_pri, RSA_pri) != 1)
    {
        appendError_f("Unable to generate key with RSA key.");
        return;
    }
    keyGenerated_pri = true;
}


void sslUtils_c::generateKeyCertificate_f()
{
    if (not keyGenerated_pri)
    {
        appendError_f("Key wasn't generated, generate Key first.");
        return;
    }

    X509_pri = X509_new();
    X509Initialized_pri = true;
    if(not X509_pri)
    {
        appendError_f("Unable to create X509 structure.");
        return;
    }

    //not necessary?
    ///* Set the serial number. */
    //ASN1_INTEGER_set(X509_get_serialNumber(x509_glo), 1);

    //This certificate is valid from now until...
    X509_gmtime_adj(X509_get_notBefore(X509_pri), 0);
    X509_gmtime_adj(X509_get_notAfter(X509_pri), 315360000L);//10 years

    /* Set the public key for our certificate. */
    X509_set_pubkey(X509_pri, key_pri);

    /* We want to copy the subject name to the issuer name. */
    //must not be freed according to openssl documentation
    X509_NAME* name = X509_get_subject_name(X509_pri);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(X509_pri, name);

    /* Actually sign the certificate with our key. */
    if(X509_sign(X509_pri, key_pri, EVP_sha1()) == 0)
    {
        appendError_f("Error signing certificate.");
        return;
    }
    certficateGenerated_pri = true;
}

//const RSA *sslUtils_c::RSA_f() const
//{
//    return RSA_pri;
//}

//const EVP_PKEY *sslUtils_c::key_f() const
//{
//    return key_pri;
//}

//const X509 *sslUtils_c::keyCertificate_f() const
//{
//    return X509_pri;
//}

std::string sslUtils_c::privateKeyStr_f()
{
    std::string str;
    if (not RSAGenerated_pri)
    {
        generateRSA_f();
    }
    if (not keyGenerated_pri)
    {
        generateKey_f();
    }

    BIO *b64 = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(b64, key_pri, NULL, NULL, 0, NULL, NULL) != 1)
    {
        appendError_f("Error generating private key string.");
    }
    else
    {
        BUF_MEM *bptr;
        BIO_get_mem_ptr(b64, &bptr);
        int length = bptr->length;
        str.resize(length, '\0');
        auto result(BIO_read(b64, &str[0], length));
    }

//    std::cout << "length " << length << std::endl;
//    std::cout << "result " << result << std::endl;
//    std::cout << "key " << test << std::endl;
    BIO_free(b64);

    return str;
}

std::string sslUtils_c::publicKeyStr_f()
{
    std::string str;
    if (not RSAGenerated_pri)
    {
        generateRSA_f();
    }
    if (not keyGenerated_pri)
    {
        generateKey_f();
    }

    BIO *b64 = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(b64, key_pri) != 1)
    {
        appendError_f("Error generating public key string.");
    }
    else
    {
        BUF_MEM *bptr;
        BIO_get_mem_ptr(b64, &bptr);
        int length = bptr->length;
        str.resize(length, '\0');
        auto result(BIO_read(b64, &str[0], length));
    }

    BIO_free(b64);

    return str;
}

std::string sslUtils_c::keyCertificateStr_f()
{
    std::string str;
    if (not RSAGenerated_pri)
    {
        generateRSA_f();
    }
    if (not keyGenerated_pri)
    {
        generateKey_f();
    }
    if (not certficateGenerated_pri)
    {
        generateKeyCertificate_f();
    }
    BIO *b64 = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509(b64, X509_pri) != 1)
    {
        appendError_f("Error generating certificate string.");
    }
    else
    {
        BUF_MEM *bptr;
        BIO_get_mem_ptr(b64, &bptr);
        int length = bptr->length;
        str.resize(length, '\0');
        auto result(BIO_read(b64, &str[0], length));
    }

    BIO_free(b64);

    return str;
}

}

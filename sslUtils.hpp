#ifndef SSLUTILSSO_SSLUTILS_HPP
#define SSLUTILSSO_SSLUTILS_HPP

#include "comuso/baseClassTemplate.hpp"
#include "crossPlatformMacros.hpp"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <string>


class EXPIMP_SSLUTILSSO sslUtils_c : public eines::baseClass::baseClass_c
{
    //this one is required for the others
    bool RSAGenerated_pri = false;
    //requires RSA
    bool keyGenerated_pri = false;
    //this one requires a key
    bool certficateGenerated_pri = false;

    EVP_PKEY* key_pri = nullptr;
    bool keyInitialized_pri = false;
    //certificate
    X509* X509_pri = nullptr;
    bool X509Initialized_pri = false;

    //
    BIGNUM* bn_pri = nullptr;
    bool bnInitialized_pri = false;
    RSA* RSA_pri = nullptr;
    bool RSAInitialized_pri = false;

    void freeOpensslStuff_f();

public:
    sslUtils_c() = default;
    ~sslUtils_c();

    void generateRSA_f();
    void generateKey_f();
    void generateKeyCertificate_f();
    //comment these, no use for them right now 20171016
//    const RSA* RSA_f() const;
//    const EVP_PKEY* key_f() const;
//    const X509* keyCertificate_f() const;

    //TODO? fuse this 3 in one and use an enum?
    //calling any of these will do/generate the necessary stuff
    //calling them more than once won't "regenerate" stuff, create another class object for that
    std::string privateKeyStr_f();
    std::string publicKeyStr_f();
    std::string keyCertificateStr_f();

    //comment these, no use for them right now 20171016
//    bool RSAGenerated_f() const;
//    bool keyGenerated_f() const;
//    bool certficateGenerated_f() const;
};


#endif // SSLUTILSSO_SSLUTILS_HPP

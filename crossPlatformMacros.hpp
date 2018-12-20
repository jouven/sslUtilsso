//because windows sucks...

#ifndef SSLUTILSSO_CROSSPLATFORMMACROS_HPP
#define SSLUTILSSO_CROSSPLATFORMMACROS_HPP

#include <QtCore/QtGlobal>

//remember to define this variable in the .pro file
#if defined(SSLUTILSSO_LIBRARY)
#  define EXPIMP_SSLUTILSSO Q_DECL_EXPORT
#else
#  define EXPIMP_SSLUTILSSO Q_DECL_IMPORT
#endif

#endif // SSLUTILSSO_CROSSPLATFORMMACROS_HPP

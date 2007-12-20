%bcond_without  lib

%define major   3
%define libname %mklibname %{name} %{major}
%define develname %mklibname -d %{name}
%define sdevelname %mklibname -d -s %{name}
%define cvsver  3_11_7

Name:           nss
Version:        3.11.7
Release:        %mkrel 3
Epoch:          2
Summary:        Netscape Security Services
Group:          System/Libraries
License:        MPL/GPL/LGPL
URL:            http://www.mozilla.org/projects/security/pki/nss/index.html
Source0:        ftp://ftp.mozilla.org/pub/mozilla.org/security/nss/releases/NSS_%{cvsver}_RTM/src/nss-%{version}.tar.gz
Source1:        nss.pc
Source2:        nss-config.in
Source3:        blank-cert8.db
Source4:        blank-key3.db
Source5:        blank-secmod.db
Source6:        nss-clobber.sh
# https://www.verisign.com/support/verisign-intermediate-ca/secure-site-intermediate/index.html
# converted from PEM to DER format with openssl command:
# openssl x509 -in cert.pem -inform PEM -outform DER -out cert.der
# this way we can avoid a buildrequires for openssl
Source7:        verisign-class-3-secure-server-ca.der
# Brasilian government certificate
# verified in person with a government official
Source8:        http://www.icpbrasil.gov.br/certificadoACRaiz.crt
Patch0:         nss-no-rpath.patch
Patch1:         nss-smartcard-auth.patch
Patch2:         nss-bug180726.patch
Patch3:         nss-fixrandom.patch
%if %mdkversion >= 200700
BuildRequires:  rootcerts >= 20070713
%endif
BuildRequires:  libnspr-devel
BuildRequires:  libz-devel
BuildRequires:  zip
Conflicts:      perl-PAR
Buildroot:	%{_tmppath}/%{name}-%{version}-%{release}-root

%description
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and server
applications. Applications built with NSS can support SSL v2 and v3,
TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509 v3 certificates, and
other security standards. For detailed information on standards supported, see
http://www.mozilla.org/projects/security/pki/nss/overview.html.
%if %without lib

Note: This package currently contains the NSS binaries only. The
libraries have been not been included due to conflicts with the Mozilla
libraries.
%endif

%if %with lib
%package -n %{libname}
Summary:        Network Security Services (NSS)
Group:          System/Libraries
Provides:       mozilla-nss = %{epoch}:%{version}-%{release}
Requires(post): nss
Requires(post): rpm-helper

%description -n %{libname}
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled server
applications. Applications built with NSS can support SSL v2 and v3,
TLS, PKCS #5, PKCS #7, PKCS #11, PKCS
#12, S/MIME, X.509 v3 certificates, and other security standards. For
detailed information on standards supported, see
http://www.mozilla.org/projects/security/pki/nss/overview.html.

%package -n %{develname}
Summary:        Network Security Services (NSS) - development files
Group:          Development/C++
Requires:       %{libname} = %{epoch}:%{version}-%{release}
Requires:       libnspr-devel
Provides:       libnss-devel = %{epoch}:%{version}-%{release}
Provides:       nss-devel = %{epoch}:%{version}-%{release}
Obsoletes:	%{libname}-devel

%description -n %{develname}
Header files to doing development with Network Security Services.

%package -n %{sdevelname}
Summary:        Network Security Services (NSS) - static libraries
Group:          Development/C++
Requires:       %{libname} = %{epoch}:%{version}-%{release}
Requires:       %{develname} = %{epoch}:%{version}-%{release}
Requires:       nspr-devel
Provides:       libnss-static-devel = %{epoch}:%{version}-%{release}
Provides:       nss-static-devel = %{epoch}:%{version}-%{release}
Conflicts:      libopenssl-static-devel
Obsoletes:	%{libname}-static-devel

%description -n %{sdevelname}
Static libraries for doing development with Network Security Services.
%endif

%prep
%setup -q
sh %{SOURCE6} > /dev/null
%patch0 -p0
%patch1 -p0 -b .smartcard-auth.patch
%patch2 -p0
%patch3 -p0

%build
export BUILD_OPT=1
export OPTIMIZER="%{optflags} -fno-strict-aliasing"
export XCFLAGS="%{optflags} -fno-strict-aliasing"
export LIBDIR=%{_libdir}
export USE_SYSTEM_ZLIB=1
export ZLIB_LIBS="-lz"
export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1
export NSPR_INCLUDE_DIR=`%{_bindir}/pkg-config --cflags-only-I nspr | %{__sed} 's/-I//'`
export NSPR_LIB_DIR=`%{_bindir}/pkg-config --libs-only-L nspr | %{__sed} 's/-L//'`

%ifarch x86_64 ppc64 ia64 s390x
export USE_64=1
%endif

# Parallel is broken as of 3.11.4 :(
%{__make} -C ./mozilla/security/coreconf
%{__make} -C ./mozilla/security/dbm
%{__make} -C ./mozilla/security/nss

# install new Verisign intermediate certificate
# http://qa.mandriva.com/show_bug.cgi?id=29612
# use built addbuildin command to avoid having
# a buildrequires for nss
ADDBUILTIN=`%{_bindir}/find . -type f -name addbuiltin`
if [ -z "$ADDBUILTIN" ]; then
    exit 1
fi
ADDBUILTIN="$PWD/$ADDBUILTIN"
OLD="$LD_LIBRARY_PATH"
libpath=`%{_bindir}/find mozilla/dist/ -name "Linux2.*" -type d`
# to use the built libraries instead of requiring nss
# again as buildrequires
export LD_LIBRARY_PATH="$PWD/$libpath/lib"
pushd mozilla/security/nss/lib/ckfw/builtins
%if %mdkversion > 200600
%{__perl} ./certdata.perl < /etc/pki/tls/mozilla/certdata.txt
%else
$ADDBUILTIN -n "VeriSign Class 3 Secure Server CA" \
        -t CT,C,C < %{SOURCE7} >> certdata.txt
$ADDBUILTIN -n "Autoridade Certificadora Raiz Brasileira" \
        -t CT,C,C < %{SOURCE8} >> certdata.txt
%{__perl} ./certdata.perl < certdata.txt
%endif
%{__make} clean
%{__make}
popd
export LD_LIBRARY_PATH="$OLD"

%install
%{__rm} -rf %{buildroot}

cd mozilla/dist/$(uname -s)*

%{__mkdir_p} %{buildroot}%{_bindir}
%{__cp} -aL bin/* %{buildroot}%{_bindir}

%if %with lib
%{__mkdir_p} %{buildroot}%{_libdir}
%{__mkdir_p} %{buildroot}%{_includedir}/nss
%{__cp} -aL ../public/nss/* %{buildroot}%{_includedir}/nss

%{__cp} -aL lib/libcrmf.a \
            lib/libnss%{major}.so \
            lib/libfreebl%{major}.so \
            lib/libnss.a \
            lib/libnssb.a \
            lib/libnssckbi.so \
            lib/libnssckfw.a \
            lib/libsmime.a \
            lib/libsmime%{major}.so \
            lib/libsoftokn%{major}.so \
            lib/libssl.a \
            lib/libssl%{major}.so \
            %{buildroot}%{_libdir}

%{__mkdir_p} %{buildroot}%{_libdir}/pkgconfig
%{__install} %{SOURCE1} %{buildroot}%{_libdir}/pkgconfig/nss.pc
%{__perl} -pi -e 's|(^libdir=)(.*)|\1%{_libdir}|' %{buildroot}%{_libdir}/pkgconfig/nss.pc
%endif

cd ../../..

%if %with lib
export NSS_VMAJOR=`%{__cat} mozilla/security/nss/lib/nss/nss.h | %{__grep} "#define.*NSS_VMAJOR" | %{__awk} '{print $3}'`
export NSS_VMINOR=`%{__cat} mozilla/security/nss/lib/nss/nss.h | %{__grep} "#define.*NSS_VMINOR" | %{__awk} '{print $3}'`
export NSS_VPATCH=`%{__cat} mozilla/security/nss/lib/nss/nss.h | %{__grep} "#define.*NSS_VPATCH" | %{__awk} '{print $3}'`

%{__mkdir_p} %{buildroot}%{_bindir}
%{__cat} %{SOURCE2} | %{__sed} -e "s,@libdir@,%{_libdir},g" \
                               -e "s,@prefix@,%{_prefix},g" \
                               -e "s,@exec_prefix@,%{_prefix},g" \
                               -e "s,@includedir@,%{_includedir}/nss%{major},g" \
                               -e "s,@MOD_MAJOR_VERSION@,$NSS_VMAJOR,g" \
                               -e "s,@MOD_MINOR_VERSION@,$NSS_VMINOR,g" \
                               -e "s,@MOD_PATCH_VERSION@,$NSS_VPATCH,g" \
                               > %{buildroot}/%{_bindir}/nss-config
%endif

cd mozilla/security/nss/cmd/smimetools
%{__install} -m 0755 smime %{buildroot}%{_bindir}
%{__perl} -pi -e 's|/usr/local/bin|%{_bindir}|g' %{buildroot}%{_bindir}/smime
cd ../../../../..

# add docs
%{__mkdir_p} docs/SSLsample
%{__cp} -a mozilla/security/nss/cmd/SSLsample/README docs/SSLsample/

%{__mkdir_p} docs/bltest
%{__cp} -a mozilla/security/nss/cmd/bltest/tests/* docs/bltest/

%{__mkdir_p} docs/certcgi
%{__cp} -a mozilla/security/nss/cmd/certcgi/*.html docs/certcgi/
%{__cp} -a mozilla/security/nss/cmd/certcgi/HOWTO.txt docs/certcgi/

%{__mkdir_p} docs/modutil
%{__cp} -a mozilla/security/nss/cmd/modutil/*.html docs/modutil/

%{__mkdir_p} docs/signtool
%{__cp} -a mozilla/security/nss/cmd/signtool/README docs/signtool/

%{__mkdir_p} docs/signver
%{__cp} -a mozilla/security/nss/cmd/signver/examples/1/*.pl docs/signver/
%{__cp} -a mozilla/security/nss/cmd/signver/examples/1/*.html docs/signver/

%{__mkdir_p} docs/ssltap
%{__cp} -a mozilla/security/nss/cmd/ssltap/*.html docs/ssltap/

%if %with lib
# These ghost files will be generated in the post step
/bin/touch %{buildroot}%{_libdir}/libsoftokn%{major}.chk
/bin/touch %{buildroot}%{_libdir}/libfreebl%{major}.chk
%endif

# Install the empty NSS db files
%{__mkdir_p} %{buildroot}%{_sysconfdir}/pki/nssdb
%{__install} -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/pki/nssdb/cert8.db
%{__install} -m 644 %{SOURCE4} %{buildroot}%{_sysconfdir}/pki/nssdb/key3.db
%{__install} -m 644 %{SOURCE5} %{buildroot}%{_sysconfdir}/pki/nssdb/secmod.db

%{_bindir}/find docs -type f | %{_bindir}/xargs -t %{__perl} -pi -e 's/\r$//g'

%multiarch_binaries %{buildroot}%{_bindir}/nss-config

%clean
%{__rm} -rf %{buildroot}

%if %with lib
%post -n %{libname}
/sbin/ldconfig
%create_ghostfile %{_libdir}/libsoftokn%{major}.chk root root 644
%create_ghostfile %{_libdir}/libfreebl%{major}.chk root root 644
%{_bindir}/shlibsign -i %{_libdir}/libsoftokn%{major}.so >/dev/null 2>/dev/null
%{_bindir}/shlibsign -i %{_libdir}/libfreebl%{major}.so >/dev/null 2>/dev/null

%postun -n %{libname}
/sbin/ldconfig
%endif

%files
%defattr(0644,root,root,0755)
%doc docs/*
%attr(0755,root,root) %{_bindir}/addbuiltin
%attr(0755,root,root) %{_bindir}/atob
%attr(0755,root,root) %{_bindir}/bltest
%attr(0755,root,root) %{_bindir}/btoa
%attr(0755,root,root) %{_bindir}/certcgi
%attr(0755,root,root) %{_bindir}/certutil
%attr(0755,root,root) %{_bindir}/checkcert
%attr(0755,root,root) %{_bindir}/client
%attr(0755,root,root) %{_bindir}/cmsutil
%attr(0755,root,root) %{_bindir}/crlutil
%attr(0755,root,root) %{_bindir}/crmftest
%attr(0755,root,root) %{_bindir}/dbtest
%attr(0755,root,root) %{_bindir}/derdump
%attr(0755,root,root) %{_bindir}/digest
%attr(0755,root,root) %{_bindir}/fipstest
%attr(0755,root,root) %{_bindir}/makepqg
%attr(0755,root,root) %{_bindir}/mangle
%attr(0755,root,root) %{_bindir}/modutil
%attr(0755,root,root) %{_bindir}/ocspclnt
%attr(0755,root,root) %{_bindir}/oidcalc
%attr(0755,root,root) %{_bindir}/p7content
%attr(0755,root,root) %{_bindir}/p7env
%attr(0755,root,root) %{_bindir}/p7sign
%attr(0755,root,root) %{_bindir}/p7verify
%attr(0755,root,root) %{_bindir}/pk11mode
%attr(0755,root,root) %{_bindir}/pk12util
%attr(0755,root,root) %{_bindir}/pp
%attr(0755,root,root) %{_bindir}/rsaperf
%attr(0755,root,root) %{_bindir}/sdrtest
%attr(0755,root,root) %{_bindir}/selfserv
%attr(0755,root,root) %{_bindir}/server
%attr(0755,root,root) %{_bindir}/shlibsign
%attr(0755,root,root) %{_bindir}/signtool
%attr(0755,root,root) %{_bindir}/signver
%attr(0755,root,root) %{_bindir}/smime
%attr(0755,root,root) %{_bindir}/ssltap
%attr(0755,root,root) %{_bindir}/strsclnt
%attr(0755,root,root) %{_bindir}/symkeyutil
%attr(0755,root,root) %{_bindir}/tstclnt
%attr(0755,root,root) %{_bindir}/vfychain
%attr(0755,root,root) %{_bindir}/vfyserv
%dir %{_sysconfdir}/pki/nssdb
%config(noreplace) %{_sysconfdir}/pki/nssdb/cert8.db
%config(noreplace) %{_sysconfdir}/pki/nssdb/key3.db
%config(noreplace) %{_sysconfdir}/pki/nssdb/secmod.db

%if %with lib
%files -n %{libname}
%defattr(0755,root,root,0755)
%{_libdir}/libfreebl%{major}.so
%{_libdir}/libnss%{major}.so
%{_libdir}/libnssckbi.so
%{_libdir}/libsmime%{major}.so
%{_libdir}/libsoftokn%{major}.so
%{_libdir}/libssl%{major}.so
%defattr(0644,root,root,0755)
%ghost %{_libdir}/libsoftokn%{major}.chk
%ghost %{_libdir}/libfreebl%{major}.chk

%files -n %{develname}
%defattr(0644,root,root,0755)
%attr(0755,root,root) %{_bindir}/nss-config
%attr(0755,root,root) %{multiarch_bindir}/nss-config
%dir %{_includedir}/nss
%{_includedir}/nss/base64.h
%{_includedir}/nss/blapit.h
%{_includedir}/nss/cert.h
%{_includedir}/nss/certdb.h
%{_includedir}/nss/certt.h
%{_includedir}/nss/ciferfam.h
%{_includedir}/nss/cmmf.h
%{_includedir}/nss/cmmft.h
%{_includedir}/nss/cms.h
%{_includedir}/nss/cmsreclist.h
%{_includedir}/nss/cmst.h
%{_includedir}/nss/crmf.h
%{_includedir}/nss/crmft.h
%{_includedir}/nss/cryptohi.h
%{_includedir}/nss/cryptoht.h
%{_includedir}/nss/ecl-exp.h
%{_includedir}/nss/hasht.h
%{_includedir}/nss/jar-ds.h
%{_includedir}/nss/jar.h
%{_includedir}/nss/jarfile.h
%{_includedir}/nss/key.h
%{_includedir}/nss/keyhi.h
%{_includedir}/nss/keyt.h
%{_includedir}/nss/keythi.h
%{_includedir}/nss/nss.h
%{_includedir}/nss/nssb64.h
%{_includedir}/nss/nssb64t.h
%{_includedir}/nss/nssbase.h
%{_includedir}/nss/nssbaset.h
%{_includedir}/nss/nssck.api
%{_includedir}/nss/nssckbi.h
%{_includedir}/nss/nssckepv.h
%{_includedir}/nss/nssckft.h
%{_includedir}/nss/nssckfw.h
%{_includedir}/nss/nssckfwc.h
%{_includedir}/nss/nssckfwt.h
%{_includedir}/nss/nssckg.h
%{_includedir}/nss/nssckmdt.h
%{_includedir}/nss/nssckt.h
%{_includedir}/nss/nssilckt.h
%{_includedir}/nss/nssilock.h
%{_includedir}/nss/nsslocks.h
%{_includedir}/nss/nssrwlk.h
%{_includedir}/nss/nssrwlkt.h
%{_includedir}/nss/ocsp.h
%{_includedir}/nss/ocspt.h
%{_includedir}/nss/p12.h
%{_includedir}/nss/p12plcy.h
%{_includedir}/nss/p12t.h
%{_includedir}/nss/pk11func.h
%{_includedir}/nss/pk11pqg.h
%{_includedir}/nss/pk11priv.h
%{_includedir}/nss/pk11pub.h
%{_includedir}/nss/pk11sdr.h
%{_includedir}/nss/pkcs11.h
%{_includedir}/nss/pkcs11f.h
%{_includedir}/nss/pkcs11n.h
%{_includedir}/nss/pkcs11p.h
%{_includedir}/nss/pkcs11t.h
%{_includedir}/nss/pkcs11u.h
%{_includedir}/nss/pkcs12.h
%{_includedir}/nss/pkcs12t.h
%{_includedir}/nss/pkcs7t.h
%{_includedir}/nss/portreg.h
%{_includedir}/nss/preenc.h
%{_includedir}/nss/secasn1.h
%{_includedir}/nss/secasn1t.h
%{_includedir}/nss/seccomon.h
%{_includedir}/nss/secder.h
%{_includedir}/nss/secdert.h
%{_includedir}/nss/secdig.h
%{_includedir}/nss/secdigt.h
%{_includedir}/nss/secerr.h
%{_includedir}/nss/sechash.h
%{_includedir}/nss/secitem.h
%{_includedir}/nss/secmime.h
%{_includedir}/nss/secmod.h
%{_includedir}/nss/secmodt.h
%{_includedir}/nss/secoid.h
%{_includedir}/nss/secoidt.h
%{_includedir}/nss/secpkcs5.h
%{_includedir}/nss/secpkcs7.h
%{_includedir}/nss/secport.h
%{_includedir}/nss/shsign.h
%{_includedir}/nss/smime.h
%{_includedir}/nss/ssl.h
%{_includedir}/nss/sslerr.h
%{_includedir}/nss/sslproto.h
%{_includedir}/nss/sslt.h
%{_includedir}/nss/watcomfx.h
%{_libdir}/pkgconfig/nss.pc

%files -n %{sdevelname}
%defattr(0644,root,root,0755)
%{_libdir}/libcrmf.a
%{_libdir}/libnss.a
%{_libdir}/libnssb.a
%{_libdir}/libnssckfw.a
%{_libdir}/libsmime.a
%{_libdir}/libssl.a
%endif

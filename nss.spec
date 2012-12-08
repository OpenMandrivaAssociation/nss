%bcond_without  lib

%define major 3
%define libname %mklibname %{name} %{major}
%define libfreebl %mklibname freebl %{major}
%define develname %mklibname -d %{name}
%define sdevelname %mklibname -d -s %{name}
%define cvsver 3_13

%define nspr_libname %mklibname nspr 4
%define	nspr_version 4.9.0

# this seems fragile, so require the exact version or later (#58754)
%define sqlite3_version %(pkg-config --modversion sqlite3 &>/dev/null && pkg-config --modversion sqlite3 2>/dev/null || echo 0)
%define nspr_version %(pkg-config --modversion nspr &>/dev/null && pkg-config --modversion nspr 2>/dev/null || echo 0)

%define build_empty 0
%{?_with_empty:   %{expand: %%global build_empty 1}}
%{?_without_empty:   %{expand: %%global build_empty 0}}

Name:		nss
Epoch:		2
Version:	3.13.6
Release:	5
Summary:	Netscape Security Services
Group:		System/Libraries
License:	MPL or GPLv2+ or LGPLv2+
URL:		http://www.mozilla.org/projects/security/pki/nss/index.html
Source0:	ftp://ftp.mozilla.org/pub/mozilla.org/security/nss/releases/NSS_%{cvsver}_RTM/src/nss-%{version}.tar.gz
Source1:	nss.pc.in
Source2:	nss-config.in
Source3:	blank-cert8.db
Source4:	blank-key3.db
Source5:	blank-secmod.db
Source6:	certdata_empty.txt
# https://www.verisign.com/support/verisign-intermediate-ca/secure-site-intermediate/index.html
# converted from PEM to DER format with openssl command:
# openssl x509 -in cert.pem -inform PEM -outform DER -out cert.der
# this way we can avoid a buildrequires for openssl
Source7:	verisign-class-3-secure-server-ca.der
# Brasilian government certificate
# verified in person with a government official
Source8:	http://www.icpbrasil.gov.br/certificadoACRaiz.crt
Patch0:		nss-no-rpath.patch
Patch1:		nss-fixrandom.patch
Patch3:		nss-3.12.7-format_not_a_string_literal_and_no_format_arguments.patch
Patch4:		renegotiate-transitional.patch
BuildRequires:	rootcerts >= 1:20120218.00
BuildRequires:	nspr-devel >= 2:4.9.0
BuildRequires:	zlib-devel
BuildRequires:	sqlite3-devel >= 3.7.7.1
BuildRequires:	zip

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

%package shlibsign
Summary:	Netscape Security Services - shlibsign
Group:		System/Libraries
Conflicts:	%{name} < 2:3.13.1-2

%description shlibsign
This package contains the binary shlibsign needed by libfreebl3
and libsoftokn3.

%if %with lib
%package -n %{libname}
Summary:	Network Security Services (NSS)
Group:		System/Libraries

%description -n %{libname}
This package contains the shared libraries libnss3, libnssckbi, libnssdbm3,
libnssutil3, libsmime3, and libssl3.

%package -n %{libfreebl}
Summary:	Network Security Services (NSS)
Group:		System/Libraries
Requires(post): nss-shlibsign
Requires(post): rpm-helper
Conflicts: %{_lib}nss3 < 2:3.13.1-5

%description -n %{libfreebl}
This package contains the shared libraries libfreebl3 and libsoftokn3.

%package -n %{develname}
Summary:	Network Security Services (NSS) - development files
Group:		Development/C++
Requires:	%{libname} >= %{epoch}:%{version}-%{release}
Requires:	%{libfreebl} >= %{epoch}:%{version}-%{release}
Provides:	nss-devel = %{epoch}:%{version}-%{release}
%rename %{libname}-devel

%description -n %{develname}
Header files to doing development with Network Security Services.

%package -n %{sdevelname}
Summary:	Network Security Services (NSS) - static libraries
Group:		Development/C++
Requires:	%{libname} >= %{epoch}:%{version}-%{release}
Requires:	%{develname} >= %{epoch}:%{version}-%{release}
Provides:	nss-static-devel = %{epoch}:%{version}-%{release}
Conflicts:	libopenssl-static-devel
%rename %{libname}-static-devel

%description -n %{sdevelname}
Static libraries for doing development with Network Security Services.
%endif

%prep

%setup -q
%patch0 -p0
%patch1 -p0
%patch3 -p1
%patch4 -p0 -b .transitional

find . -type d -perm 0700 -exec chmod 755 {} \;
find . -type f -perm 0555 -exec chmod 755 {} \;
find . -type f -perm 0444 -exec chmod 644 {} \;
find . -name '*.h' -executable -exec chmod -x {} \;
find . -name '*.c' -executable -exec chmod -x {} \;

%build
%setup_compile_flags
export BUILD_OPT=1
export OPTIMIZER="%{optflags}"
export XCFLAGS="%{optflags}"
export ARCHFLAG="$LDFLAGS"
export LIBDIR=%{_libdir}
export USE_SYSTEM_ZLIB=1
export ZLIB_LIBS="-lz"
export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1
export NSPR_INCLUDE_DIR=`%{_bindir}/pkg-config --cflags-only-I nspr | sed 's/-I//'`
export NSPR_LIB_DIR=`%{_bindir}/pkg-config --libs-only-L nspr | sed 's/-L//'`
export MOZILLA_CLIENT=1
export NS_USE_GCC=1
export NSS_USE_SYSTEM_SQLITE=1
export NSS_ENABLE_ECC=1
%ifarch x86_64 ppc64 ia64 s390x
export USE_64=1
%endif

%if %{build_empty}
# (oe) the "trust no one" scenario, it goes like:
# 1. mv /%{_lib}/libnssckbi.so /%{_lib}/libnssckbi.so.BAK
# 2. mv /%{_lib}/libnssckbi_empty.so /%{_lib}/libnssckbi.so
# 3. restart ff/tb
# it has to be done manually for now, but at least we have a way for 
# users to quickly mitigate future problems, or whatever :-)

pushd mozilla/security/nss/lib/ckfw/builtins
%{__perl} ./certdata.perl < %{SOURCE6}
popd
%endif

# Parallel is broken as of 3.11.4 :(
%make -j1 -C ./mozilla/security/nss \
	build_coreconf \
	build_dbm \
	all

%if %{build_empty}
# tuck away the empty libnssckbi.so library
cp -p mozilla/security/nss/lib/ckfw/builtins/Linux*/libnssckbi.so libnssckbi_empty.so
%endif

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
libpath=`%{_bindir}/find mozilla/dist/ -name "Linux*" -type d`
# to use the built libraries instead of requiring nss
# again as buildrequires
export LD_LIBRARY_PATH="$PWD/$libpath/lib"

pushd mozilla/security/nss/lib/ckfw/builtins

# (oe) for reference:
# *ALL* of the root CA certs are hard coded into the libnssckbi.so library.
# So, for Mandriva we can add/remove certs easily in the rootcerts package. Please
# checkout and examine the rootcerts package.
# Once this has been done and the new rootcerts package has been installed this
# package (nss) has to be rebuilt to pickup the changes made. The "recreate 
# certificates" lines below generates a new certdata.c source containing the root
# CA certs for mozilla.
# *ALL* of the mozilla based softwares that support SSL has to link against
# the NSS library.
# recreate certificates
%{__perl} ./certdata.perl < /etc/pki/tls/mozilla/certdata.txt

%make clean
%make -j1

popd
export LD_LIBRARY_PATH="$OLD"

%install
pushd mozilla/dist/$(uname -s)*

%{__mkdir_p} %{buildroot}%{_bindir}
%{__cp} -aL bin/* %{buildroot}%{_bindir}

%if %with lib
%{__mkdir_p} %{buildroot}%{_libdir}
%{__mkdir_p} %{buildroot}/%{_lib}
%{__mkdir_p} %{buildroot}%{_includedir}/nss
%{__cp} -aL ../public/nss/* %{buildroot}%{_includedir}/nss

%{__cp} -aL lib/libcrmf.a \
            lib/libnss.a \
            lib/libnssb.a \
            lib/libnssckbi.so \
            lib/libnssckfw.a \
	    lib/libnssutil.a \
            lib/libsmime.a \
            lib/libssl.a \
            %{buildroot}%{_libdir}

# Copy the binary libraries we want
for file in libsoftokn3.so libfreebl3.so libnss3.so libnssutil3.so \
            libssl3.so libsmime3.so libnssckbi.so libnssdbm3.so
do
  %{__install} -m 755 lib/$file %{buildroot}/%{_lib}
  ln -sf ../../%{_lib}/$file %{buildroot}%{_libdir}/$file
done

# These ghost files will be generated in the post step
# Make sure chk files can be found in both places
for file in libsoftokn3.chk libfreebl3.chk
do
  touch %{buildroot}/%{_lib}/$file
  ln -s ../../%{_lib}/$file %{buildroot}%{_libdir}/$file
done

%{__mkdir_p} %{buildroot}%{_libdir}/pkgconfig
cat %{SOURCE1} | sed -e "s,%%libdir%%,%{_libdir},g" \
                          -e "s,%%prefix%%,%{_prefix},g" \
                          -e "s,%%exec_prefix%%,%{_prefix},g" \
                          -e "s,%%includedir%%,%{_includedir}/nss,g" \
                          -e "s,%%NSPR_VERSION%%,%{nspr_version},g" \
                          -e "s,%%NSS_VERSION%%,%{version},g" > \
                          %{buildroot}%{_libdir}/pkgconfig/nss.pc
%endif

popd

%if %with lib
export NSS_VMAJOR=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VMAJOR" | awk '{print $3}'`
export NSS_VMINOR=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VMINOR" | awk '{print $3}'`
export NSS_VPATCH=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VPATCH" | awk '{print $3}'`

%{__mkdir_p} %{buildroot}%{_bindir}
cat %{SOURCE2} | sed -e "s,@libdir@,%{_libdir},g" \
                               -e "s,@prefix@,%{_prefix},g" \
                               -e "s,@exec_prefix@,%{_prefix},g" \
                               -e "s,@includedir@,%{_includedir}/nss%{major},g" \
                               -e "s,@MOD_MAJOR_VERSION@,$NSS_VMAJOR,g" \
                               -e "s,@MOD_MINOR_VERSION@,$NSS_VMINOR,g" \
                               -e "s,@MOD_PATCH_VERSION@,$NSS_VPATCH,g" \
                               > %{buildroot}/%{_bindir}/nss-config
%endif

pushd mozilla/security/nss/cmd/smimetools
%{__install} -m 0755 smime %{buildroot}%{_bindir}
%{__perl} -pi -e 's|/usr/local/bin|%{_bindir}|g' %{buildroot}%{_bindir}/smime
popd

# add docs
%{__mkdir_p} docs/SSLsample
#%{__cp} -a mozilla/security/nss/cmd/SSLsample/README docs/SSLsample/

%{__mkdir_p} docs/bltest
cp -a mozilla/security/nss/cmd/bltest/tests/* docs/bltest/
chmod -R a+r docs

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

# Install the empty NSS db files
%{__mkdir_p} %{buildroot}%{_sysconfdir}/pki/nssdb
%{__install} -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/pki/nssdb/cert8.db
%{__install} -m 644 %{SOURCE4} %{buildroot}%{_sysconfdir}/pki/nssdb/key3.db
%{__install} -m 644 %{SOURCE5} %{buildroot}%{_sysconfdir}/pki/nssdb/secmod.db

%{_bindir}/find docs -type f | %{_bindir}/xargs -t %{__perl} -pi -e 's/\r$//g'

%if %{build_empty}
# install the empty libnssckbi.so library (use alternatives?)
install -m0755 libnssckbi_empty.so %{buildroot}/%{_lib}/libnssckbi_empty.so
%endif

%multiarch_binaries %{buildroot}%{_bindir}/nss-config

%if %with lib
%posttrans -n %{libfreebl}
%create_ghostfile /%{_lib}/libsoftokn%{major}.chk root root 644
%create_ghostfile /%{_lib}/libfreebl%{major}.chk root root 644
%{_bindir}/shlibsign -i /%{_lib}/libsoftokn%{major}.so >/dev/null 2>/dev/null
%{_bindir}/shlibsign -i /%{_lib}/libfreebl%{major}.so >/dev/null 2>/dev/null
%endif

%files
%doc docs/*
%attr(0755,root,root) %{_bindir}/addbuiltin
%attr(0755,root,root) %{_bindir}/atob
%attr(0755,root,root) %{_bindir}/baddbdir
%attr(0755,root,root) %{_bindir}/bltest
%attr(0755,root,root) %{_bindir}/btoa
%attr(0755,root,root) %{_bindir}/certcgi
%attr(0755,root,root) %{_bindir}/certutil
%attr(0755,root,root) %{_bindir}/checkcert
%attr(0755,root,root) %{_bindir}/chktest
%attr(0755,root,root) %{_bindir}/cmsutil
%attr(0755,root,root) %{_bindir}/conflict
%attr(0755,root,root) %{_bindir}/crlutil
%attr(0755,root,root) %{_bindir}/crmftest
%attr(0755,root,root) %{_bindir}/dbtest
%attr(0755,root,root) %{_bindir}/derdump
%attr(0755,root,root) %{_bindir}/dertimetest
%attr(0755,root,root) %{_bindir}/digest
%attr(0755,root,root) %{_bindir}/encodeinttest
%attr(0755,root,root) %{_bindir}/fipstest
%attr(0755,root,root) %{_bindir}/makepqg
%attr(0755,root,root) %{_bindir}/mangle
%attr(0755,root,root) %{_bindir}/modutil
%attr(0755,root,root) %{_bindir}/multinit
%attr(0755,root,root) %{_bindir}/nonspr10
%attr(0755,root,root) %{_bindir}/ocspclnt
%attr(0755,root,root) %{_bindir}/oidcalc
%attr(0755,root,root) %{_bindir}/p7content
%attr(0755,root,root) %{_bindir}/p7env
%attr(0755,root,root) %{_bindir}/p7sign
%attr(0755,root,root) %{_bindir}/p7verify
%attr(0755,root,root) %{_bindir}/pk11mode
%attr(0755,root,root) %{_bindir}/pk12util
%attr(0755,root,root) %{_bindir}/pp
%attr(0755,root,root) %{_bindir}/remtest
%attr(0755,root,root) %{_bindir}/rsaperf
%attr(0755,root,root) %{_bindir}/sdrtest
%attr(0755,root,root) %{_bindir}/selfserv
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

%files shlibsign
%attr(0755,root,root) %{_bindir}/shlibsign

%if %with lib
%files -n %{libfreebl}
/%{_lib}/libfreebl%{major}.so
/%{_lib}/libsoftokn%{major}.so
%defattr(0644,root,root,0755)
%ghost /%{_lib}/libfreebl%{major}.chk
%ghost /%{_lib}/libsoftokn%{major}.chk

%files -n %{libname}
/%{_lib}/libnss%{major}.so
/%{_lib}/libnssckbi.so
%if %{build_empty}
/%{_lib}/libnssckbi_empty.so
%endif
/%{_lib}/libnssutil%{major}.so
/%{_lib}/libnssdbm%{major}.so
/%{_lib}/libsmime%{major}.so
/%{_lib}/libssl%{major}.so

%files -n %{develname}
%defattr(0644,root,root,0755)
%attr(0755,root,root) %{_bindir}/nss-config
%attr(0755,root,root) %{multiarch_bindir}/nss-config
%_libdir/*.so
%dir %{_includedir}/nss
%{_includedir}/nss/base64.h
%{_includedir}/nss/blapit.h
%{_includedir}/nss/certdb.h
%{_includedir}/nss/cert.h
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
%{_includedir}/nss/jarfile.h
%{_includedir}/nss/jar.h
%{_includedir}/nss/key.h
%{_includedir}/nss/keyhi.h
%{_includedir}/nss/keyt.h
%{_includedir}/nss/keythi.h
%{_includedir}/nss/nssb64.h
%{_includedir}/nss/nssb64t.h
%{_includedir}/nss/nssbase.h
%{_includedir}/nss/nssbaset.h
%{_includedir}/nss/nssck.api
%{_includedir}/nss/nssckbi.h
%{_includedir}/nss/nssckepv.h
%{_includedir}/nss/nssckft.h
%{_includedir}/nss/nssckfwc.h
%{_includedir}/nss/nssckfw.h
%{_includedir}/nss/nssckfwt.h
%{_includedir}/nss/nssckg.h
%{_includedir}/nss/nssckmdt.h
%{_includedir}/nss/nssckt.h
%{_includedir}/nss/nss.h
%{_includedir}/nss/nssilckt.h
%{_includedir}/nss/nssilock.h
%{_includedir}/nss/nsslocks.h
%{_includedir}/nss/nsslowhash.h
%{_includedir}/nss/nssrwlk.h
%{_includedir}/nss/nssrwlkt.h
%{_includedir}/nss/nssutil.h
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
%{_includedir}/nss/pkcs11f.h
%{_includedir}/nss/pkcs11.h
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
%{_includedir}/nss/sslerr.h
%{_includedir}/nss/ssl.h
%{_includedir}/nss/sslproto.h
%{_includedir}/nss/sslt.h
%{_includedir}/nss/utilrename.h
%{_libdir}/pkgconfig/nss.pc
%{_libdir}/libsoftokn%{major}.chk
%{_libdir}/libfreebl%{major}.chk

%files -n %{sdevelname}
%defattr(0644,root,root,0755)
%{_libdir}/libcrmf.a
%{_libdir}/libnss.a
%{_libdir}/libnssutil.a
%{_libdir}/libnssb.a
%{_libdir}/libnssckfw.a
%{_libdir}/libsmime.a
%{_libdir}/libssl.a
%endif


%changelog
* Tue Jun 05 2012 Oden Eriksson <oeriksson@mandriva.com> 2:3.13.5-1mdv2012.0
+ Revision: 802609
- 3.13.5

* Mon Apr 09 2012 Oden Eriksson <oeriksson@mandriva.com> 2:3.13.4-1
+ Revision: 789950
- 3.13.4
- fix deps
- revert rpm5 only crap

* Wed Mar 07 2012 Per Ãyvind Karlsen <peroyvind@mandriva.org> 2:3.13.3-2
+ Revision: 782704
- rebuild with internal dependency generator

* Sat Mar 03 2012 Oden Eriksson <oeriksson@mandriva.com> 2:3.13.3-1
+ Revision: 782020
- 3.13.3

* Tue Feb 21 2012 Dmitry Mikhirev <dmikhirev@mandriva.org> 2:3.13.2-1
+ Revision: 778646
- new version 3.13.2

  + Matthew Dawkins <mattydaw@mandriva.org>
    - split out libfreebl lib pkg
    - this should address dep loop problems
    - if glibc and libc ever get properly split
    - used EVRD macro
    - moved signing of libfreebl libs to posttrans
    - updated descriptions

* Thu Jan 26 2012 Oden Eriksson <oeriksson@mandriva.com> 2:3.13.1-4
+ Revision: 769168
- bump release

* Thu Jan 26 2012 Oden Eriksson <oeriksson@mandriva.com> 2:3.13.1-3
+ Revision: 769165
- fix deps
- rebuilt to pickup the changes in rootcerts as of 2012/01/17

* Tue Jan 10 2012 Matthew Dawkins <mattydaw@mandriva.org> 2:3.13.1-2
+ Revision: 759561
- fixed shlibsign description
- split out shlibsign binary
- this helps break a huge dep LOOP
- glibc<>nss<>perl
- cleaned up spec a bit

* Sat Nov 05 2011 Oden Eriksson <oeriksson@mandriva.com> 2:3.13.1-1
+ Revision: 720519
- 3.13.1
- rediff the renegotiate-transitional patch
- drop the new_certdata.txt format patch as it is fixed since 3.13

* Wed Sep 07 2011 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.11-3
+ Revision: 698538
- pick up the fix for MFSA 2011-35

* Wed Aug 31 2011 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.11-2
+ Revision: 697592
- pick up the fix for MFSA 2011-34

* Fri Aug 12 2011 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.11-1
+ Revision: 694115
- 3.12.11
- rediffed the new_certdata.txt_format patch

* Tue May 17 2011 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.10-1
+ Revision: 675834
- allow build with the new format of the certdata.txt file from cvs
- don't build the libnssckbi_empty.so library per default
- 3.12.10
- adjust deps a bit

* Thu Apr 07 2011 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.9-5
+ Revision: 651409
- added some funny stuff :-)
- document the ssl crap in the spec file...

* Fri Mar 25 2011 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.9-4
+ Revision: 648517
- rebuilt against new certdata.txt file

* Sat Feb 26 2011 Funda Wang <fwang@mandriva.org> 2:3.12.9-3
+ Revision: 639991
- rebuild

* Wed Jan 26 2011 Funda Wang <fwang@mandriva.org> 2:3.12.9-2
+ Revision: 632997
- fix build with latest rpm (wrong definition acturally)

* Fri Jan 14 2011 Funda Wang <fwang@mandriva.org> 2:3.12.9-1
+ Revision: 631033
- new version 3.12.9

* Sat Dec 25 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.8-3mdv2011.0
+ Revision: 625024
- rebuilt to pickup rootcerts-20101202 changes
- fix #61964 (nss should depend of the latest version of nspr)

* Thu Nov 25 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.8-2mdv2011.0
+ Revision: 601067
- rebuilt to pickup the changes in rootcerts-20101119.00

* Tue Oct 12 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.8-1mdv2011.0
+ Revision: 585167
- 3.12.8
- rediffed one patch
- dropped bsolete patches

* Tue Oct 12 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.7-3mdv2011.0
+ Revision: 585103
- require the version, or later of the nspr libs nss was built against. fixes #61249

* Thu Sep 09 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.7-2mdv2011.0
+ Revision: 576968
- fix backporting to older products
- rebuilt against new rootcerts-20100827

* Sat Aug 21 2010 Funda Wang <fwang@mandriva.org> 2:3.12.7-1mdv2011.0
+ Revision: 571721
- New version 3.12.7

* Mon May 17 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.6-6mdv2010.1
+ Revision: 545022
- fix deps
- rebuilt against rootcerts-20100408.00

* Tue Apr 27 2010 Christophe Fergeau <cfergeau@mandriva.com> 2:3.12.6-5mdv2010.1
+ Revision: 539590
- rebuild so that shared libraries are properly stripped again

* Wed Apr 21 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.6-4mdv2010.1
+ Revision: 537675
- dacapo, but for the nss library

* Wed Apr 21 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.6-3mdv2010.1
+ Revision: 537664
- require the exact version of sqlite3 it was built against or a later version

* Tue Apr 13 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.6-2mdv2010.1
+ Revision: 534197
- added backporting magic for updates
- adjust deps

* Thu Apr 01 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.6-1mdv2010.1
+ Revision: 530645
- 3.12.6 (official release)

* Tue Mar 23 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.6-0.0.1mdv2010.1
+ Revision: 526884
- use a cvs snap (NSS_3_12_6_RTM)
- rediffed the sqlite patch
- added two patches from fedora

* Fri Mar 12 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.5-4mdv2010.1
+ Revision: 518394
- rebuilt to pickup changes from rootcerts-20100216.01

* Wed Feb 03 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.5-3mdv2010.1
+ Revision: 500472
- rebuilt to pickup fixes in rootcerts-20091203.04

* Sun Jan 24 2010 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.5-2mdv2010.1
+ Revision: 495471
- rebuilt against rootcerts-20091203.00

* Wed Dec 16 2009 Funda Wang <fwang@mandriva.org> 2:3.12.5-1mdv2010.1
+ Revision: 479151
- fix file list
- new version 3.12.5

* Mon Oct 19 2009 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.4-2mdv2010.0
+ Revision: 458252
- rebuilt to pickup changes from rootcerts-20090831.00-1mdv2010.0

* Mon Aug 31 2009 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.4-1mdv2010.0
+ Revision: 422988
- 3.12.4
- nuke one *.orig file

* Tue Aug 04 2009 Oden Eriksson <oeriksson@mandriva.com> 2:3.12.3.1-1mdv2010.0
+ Revision: 408938
- 3.12.3.1

* Sat May 30 2009 Tomasz Pawel Gajc <tpg@mandriva.org> 2:3.12.3-2mdv2010.0
+ Revision: 381501
- fix file list one more time

* Sat May 30 2009 Tomasz Pawel Gajc <tpg@mandriva.org> 2:3.12.3-1mdv2010.0
+ Revision: 381500
- update to new version 3.12.3
  rediff patch 4 and 5
- drop patch 6, fixed upstream
- fix file list

* Mon Mar 23 2009 Oden Eriksson <oeriksson@mandriva.com> 2:3.12-12mdv2009.1
+ Revision: 360727
- rebuilt to pickup new data from the rootcerts (20090115.00) package

* Sun Jan 25 2009 Per Ãyvind Karlsen <peroyvind@mandriva.org> 2:3.12-11mdv2009.1
+ Revision: 333523
- bump..
- increase size for string allocated by one to make room for string terminator
  (P6, fixes /usr/bin/addbuiltin SIGABRT with 'free(): invalid pointer')

* Sun Jan 25 2009 Oden Eriksson <oeriksson@mandriva.com> 2:3.12-10mdv2009.1
+ Revision: 333463
- rebuilt with a better patch for fixing -Werror=format-security (P5)
- fix broken patch

* Mon Dec 22 2008 Tomasz Pawel Gajc <tpg@mandriva.org> 2:3.12-9mdv2009.1
+ Revision: 317711
- build with %%setup_compile_flags macro
- Patch5: fix building with -Werror=format-security
- spec file clean

* Mon Dec 08 2008 Funda Wang <fwang@mandriva.org> 2:3.12-8mdv2009.1
+ Revision: 311850
- use fedora package layout (put actual .so at /lib, and devel symbolic link at /usr/lib)

* Thu Oct 23 2008 Guillaume Rousse <guillomovitch@mandriva.org> 2:3.12-7mdv2009.1
+ Revision: 296799
- remove undocumented and unexplainable conflict with perl-PAR

  + Oden Eriksson <oeriksson@mandriva.com>
    - added ugly provides due to ugly nss libnames and sonames

* Sun Aug 10 2008 Tomasz Pawel Gajc <tpg@mandriva.org> 2:3.12-5mdv2009.0
+ Revision: 270259
- fix mixture of tabs and spaces
- bump release tag
- package libnssdbm3.so, hopefully this will fix bug #42603
- export few options for nss build

  + Frederik Himpe <fhimpe@mandriva.org>
    - Fix license
    - Remove nss-clobber.sh and noexecstack patch, both are
      not necessary anymore according to RH

* Sat Aug 09 2008 Tiago Salem <salem@mandriva.com.br> 2:3.12-4mdv2009.0
+ Revision: 269769
- add -lnssutil3 to nss-config.in
- bump release

* Fri Aug 08 2008 Tiago Salem <salem@mandriva.com.br> 2:3.12-3mdv2009.0
+ Revision: 269661
- add missing -lnssutil3 to nss.pc (breaks thunderbird build)
- bump release

* Thu Aug 07 2008 Funda Wang <fwang@mandriva.org> 2:3.12-2mdv2009.0
+ Revision: 266297
- bump release
- use system sqlite3
- add nssutil.so

  + Tomasz Pawel Gajc <tpg@mandriva.org>
    - package libnssutil3.so also

* Thu Aug 07 2008 Tomasz Pawel Gajc <tpg@mandriva.org> 2:3.12-1mdv2009.0
+ Revision: 265867
- update to new version 3.12
- drop patch1, fixed upstream
- fix file list
- spec file clean

* Tue Jun 17 2008 Thierry Vignaud <tv@mandriva.org> 2:3.11.9-3mdv2009.0
+ Revision: 223350
- rebuild

  + Pixel <pixel@mandriva.com>
    - do not call ldconfig in %%post/%%postun, it is now handled by filetriggers

* Thu Feb 14 2008 Oden Eriksson <oeriksson@mandriva.com> 2:3.11.9-2mdv2008.1
+ Revision: 168377
- rebuilt to pickup new root ca's in rootcerts-20080117.00

* Thu Feb 14 2008 Marcelo Ricardo Leitner <mrl@mandriva.com> 2:3.11.9-1mdv2008.1
+ Revision: 167772
- New upstream: 3.11.9

* Thu Feb 07 2008 Per Ãyvind Karlsen <peroyvind@mandriva.org> 2:3.11.7-4mdv2008.1
+ Revision: 163760
- really fix incorrect major
- bump back release a bit since neither of previous ones went through :)
- bah! nss.pc should be working properly now! %%&#?\194?\164%%#
- grf, fix nspr version require and, libdir path and include path
- fix nss.pc so we don't ship an old, static one..

* Thu Dec 20 2007 Oden Eriksson <oeriksson@mandriva.com> 2:3.11.7-3mdv2008.1
+ Revision: 135405
- use the correct syntax for the rootcerts build dependency
- rebuilt to pickup latest rootcerts (hardcoded into the %%{_libdir}/libnssckbi.so library)

  + Thierry Vignaud <tv@mandriva.org>
    - kill re-definition of %%buildroot on Pixel's request

* Fri Jul 20 2007 Funda Wang <fwang@mandriva.org> 2:3.11.7-2mdv2008.0
+ Revision: 53912
- fix static devel requires

* Fri Jul 20 2007 Funda Wang <fwang@mandriva.org> 2:3.11.7-1mdv2008.0
+ Revision: 53885
- fix file list
- New version

* Sun Jun 24 2007 David Walluck <walluck@mandriva.org> 2:3.11.5-5mdv2008.0
+ Revision: 43748
- add patch for certdata.txt
- spec cleanup


* Wed Mar 21 2007 Andreas Hasenack <andreas@mandriva.com> 3.11.5-4mdv2007.1
+ Revision: 147547
- fix library path
- add back Brazilian Gov. certificate
- add new Verisign certificate (#29612)

* Fri Mar 09 2007 David Walluck <walluck@mandriva.org> 2:3.11.5-4mdv2007.1
+ Revision: 139555
- fix description

* Fri Mar 09 2007 David Walluck <walluck@mandriva.org> 2:3.11.5-3mdv2007.1
+ Revision: 138691
- add docs to file list (accidently removed)

* Fri Mar 09 2007 David Walluck <walluck@mandriva.org> 2:3.11.5-2mdv2007.1
+ Revision: 138688
- really enable lib
  static-devel package conflicts with libopenssl-static-devel
  use find and xargs to remove CVS directories
  use cp -a everywhere
  macros
  mark nss-config as multiarch
  fix duplicate nss-config in file list
  run shlibsign in libnss %%post (requires nss)
  use explicit file list

* Fri Mar 09 2007 David Walluck <walluck@mandriva.org> 2:3.11.5-1mdv2007.1
+ Revision: 138582
- 3.11.5

* Tue Mar 06 2007 Marcelo Ricardo Leitner <mrl@mandriva.com> 2:3.11.4-8mdv2007.1
+ Revision: 133767
- Fix lib versions on nss-config

* Tue Mar 06 2007 Marcelo Ricardo Leitner <mrl@mandriva.com> 2:3.11.4-7mdv2007.1
+ Revision: 133671
- Add support to /usr/bin/nss-config (based on Fedora's one)

* Sun Mar 04 2007 David Walluck <walluck@mandriva.org> 2:3.11.4-6mdv2007.1
+ Revision: 132567
- rebuild

* Wed Feb 21 2007 GÃ¶tz Waschk <waschk@mandriva.org> 2:3.11.4-5mdv2007.1
+ Revision: 123208
- rebuild

  + Oden Eriksson <oeriksson@mandriva.com>
    - fix deps

* Fri Feb 09 2007 Marcelo Ricardo Leitner <mrl@mandriva.com> 2:3.11.4-3mdv2007.1
+ Revision: 118491
- Added pkcs11 devel files to libnss3-devel package.

* Thu Feb 08 2007 Marcelo Ricardo Leitner <mrl@mandriva.com> 2:3.11.4-2mdv2007.1
+ Revision: 118137
- Bump epoch, so we upgrade cleanly old firefox's libnss3.
- Do not enforce (wrong) nspr version.
- Removed patch nss-system-nspr: prefer doing it via env. variables.
- Tagged as license LGPL too
- Enabled the library.
- Do not use chrpath: it is not needed, and we are using this library now.
- Fixed epoch stuff on library packages.
- Added ldconfig call to library package.

* Sat Dec 16 2006 David Walluck <walluck@mandriva.org> 1:3.11.4-1mdv2007.1
+ Revision: 98079
- 3.11.4
- Import nss

* Fri Apr 28 2006 Oden Eriksson <oeriksson@mandriva.com> 1:3.11-1mdk
- drop redundant patches; P0,P4
- drop upstream patches; P2,P3,P85
- added P50,P51 from fedora

* Fri Nov 11 2005 Oden Eriksson <oeriksson@mandriva.com> 1:3.9.2-1mdk
- rolled back to match mozilla-firefox libs
- added some patches from the mozilla-firefox package
- added P4 to teach it ~/.mozilla

* Sat Nov 05 2005 Nicolas Lécureuil <neoclust@mandriva.org> 3.10.2-3mdk
- Fix BuildRequires

* Fri Nov 04 2005 Nicolas Lécureuil <neoclust@mandriva.org> 3.10.2-2mdk
- Fix BuildRequires

* Wed Nov 02 2005 David Walluck <walluck@mandrake.org> 0:3.10.2-1mdk
- 3.10.2

* Fri Jan 28 2005 David Walluck <walluck@mandrake.org> 3.9.2-1mdk
- release


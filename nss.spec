%bcond_without  lib
%bcond_with	cross_compiling
%define url_ver	%(echo %{version}| sed -e "s|\\.|_|g")

%define major	3
%define libname	%mklibname %{name} %{major}
%define libfreebl %mklibname freebl %{major}
%define devname	%mklibname -d %{name}
%define sdevname %mklibname -d -s %{name}
%define _disable_lto 1

%define	nspr_version 4.17

# this seems fragile, so require the exact version or later (#58754)
%define sqlite3_version %(pkg-config --modversion sqlite3 &>/dev/null && pkg-config --modversion sqlite3 2>/dev/null || echo 0)
%define nspr_version %(pkg-config --modversion nspr &>/dev/null && pkg-config --modversion nspr 2>/dev/null || echo 0)

%define build_empty 0
%{?_with_empty:   %{expand: %%global build_empty 1}}
%{?_without_empty:   %{expand: %%global build_empty 0}}

Summary:	Netscape Security Services
Name:		nss
Epoch:		3
# WARNING
# We've been on 3.31 before - it causes chromium to crash on startup
# Please verify that this is fixed before updating.
Version:	3.34
Release:	1
Group:		System/Libraries
License:	MPL or GPLv2+ or LGPLv2+
Url:		http://www.mozilla.org/projects/security/pki/nss/index.html
Source0:	http://ftp.mozilla.org/pub/security/nss/releases/NSS_%{url_ver}_RTM/src/nss-%{version}.tar.gz
#Source1:	http://ftp.mozilla.org/pub/security/nss/releases/NSS_%{url_ver}_RTM/src/nss-%{version}.tar.gz.asc
Source2:	nss.pc.in
Source3:	nss-config.in
Source4:	blank-cert8.db
Source5:	blank-key3.db
Source6:	blank-secmod.db
Source7:	certdata_empty.txt
# https://www.verisign.com/support/verisign-intermediate-ca/secure-site-intermediate/index.html
# converted from PEM to DER format with openssl command:
# openssl x509 -in cert.pem -inform PEM -outform DER -out cert.der
# this way we can avoid a buildrequires for openssl
Source8:	verisign-class-3-secure-server-ca.der
# Brasilian government certificate
# verified in person with a government official
Source9:	http://www.icpbrasil.gov.br/certificadoACRaiz.crt
Patch0:		nss-no-rpath.patch
Patch2:		renegotiate-transitional.patch
# (tpg) be carefull with last nspr4-4.10 because prtypes.h was moved to include/nspr4/
Patch4:		nss-3.15.1-correct-path-to-prtypes.h.patch

BuildRequires:	rootcerts >= 1:20120218.00
BuildRequires:	zip
BuildRequires:	pkgconfig(nspr)
BuildRequires:	pkgconfig(sqlite3)
BuildRequires:	pkgconfig(zlib)

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
Requires(posttrans): nss-shlibsign
Requires(posttrans): rpm-helper
Conflicts: %{_lib}nss3 < 2:3.13.1-5

%description -n %{libfreebl}
This package contains the shared libraries libfreebl3 and libsoftokn3.

%package -n %{devname}
Summary:	Network Security Services (NSS) - development files
Group:		Development/C++
Requires:	%{libname} >= %{epoch}:%{version}-%{release}
Requires:	%{libfreebl} >= %{epoch}:%{version}-%{release}
Provides:	nss-devel = %{epoch}:%{version}-%{release}
%rename %{libname}-devel

%description -n %{devname}
Header files to doing development with Network Security Services.

%package -n %{sdevname}
Summary:	Network Security Services (NSS) - static libraries
Group:		Development/C++
Requires:	%{libname} >= %{epoch}:%{version}-%{release}
Requires:	%{devname} >= %{epoch}:%{version}-%{release}
Provides:	nss-static-devel = %{epoch}:%{version}-%{release}
Conflicts:	libopenssl-static-devel
%rename %{libname}-static-devel

%description -n %{sdevname}
Static libraries for doing development with Network Security Services.
%endif

%prep
%setup -q
%apply_patches

find . -type d -perm 0700 -exec chmod 755 {} \;
find . -type f -perm 0555 -exec chmod 755 {} \;
find . -type f -perm 0444 -exec chmod 644 {} \;
find . -name '*.h' -executable -exec chmod -x {} \;
find . -name '*.c' -executable -exec chmod -x {} \;

# remove hardcoded gcc
sed -i 's!gcc!%{__cc}!g' nss/coreconf/Linux.mk

%build
%serverbuild
%setup_compile_flags
export CC=%{__cc}
export BUILD_OPT=1
export OPTIMIZER="%{optflags}"
export XCFLAGS="%{optflags} -Wno-error"
export ARCHFLAG="$LDFLAGS"
export LIBDIR=%{_libdir}
export USE_SYSTEM_ZLIB=1
export ZLIB_LIBS="-lz"
export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1
export NSPR_INCLUDE_DIR=`%{_bindir}/pkg-config --cflags-only-I nspr | sed 's/-I//'`
export NSPR_LIB_DIR=`%{_bindir}/pkg-config --libs-only-L nspr | sed 's/-L//'`
export MOZILLA_CLIENT=1
export NSS_USE_SYSTEM_SQLITE=1
export NSS_ENABLE_ECC=1

# external tests are causing build problems because they access ssl internal types
# TODO: Investigate as there may be a better solution
export NSS_DISABLE_GTESTS=1

%if %{build_empty}
# (oe) the "trust no one" scenario, it goes like:
# 1. mv /%{_lib}/libnssckbi.so /%{_lib}/libnssckbi.so.BAK
# 2. mv /%{_lib}/libnssckbi_empty.so /%{_lib}/libnssckbi.so
# 3. restart ff/tb
# it has to be done manually for now, but at least we have a way for
# users to quickly mitigate future problems, or whatever :-)

pushd nss/lib/ckfw/builtins
perl ./certdata.perl %{SOURCE7}
popd
%endif

%if %cross_compiling
	# Compile tools used at build time (nsinstall) in native
	# mode before setting up the environment for crosscompiling
	export USE_64=1
	make -j1 -C ./nss \
		build_coreconf build_dbm all

	CPU_ARCH="%_target_cpu"
	if echo $CPU_ARCH |grep -qE '(i.86|pentium.|athlon)'; then
		CPU_ARCH=x86
	fi
	export CPU_ARCH
%endif

export NATIVE_CC=%{_bindir}/clang
export TARGETCC="%{__cc}"
export TARGETCCC="%{__cxx}"
export TARGETRANLIB="%{__ranlib}"
%ifarch x86_64 ppc64 ia64 s390x aarch64
export USE_64=1
%else
unset USE_64 || :
%endif

# Parallel is broken as of 3.11.4 :(
#make -j1 -C ./nss/coreconf ./nss/lib/dbm ./nss \
#	TARGETCC="$TARGETCC" \
#	TARGETCCC="$TARGETCCC" \
#	TARGETRANLIB="$TARGETRANLIB" \
#	AR="%__ar cr \"\$@\"" \
#%if %cross_compiling
#	CPU_ARCH="$CPU_ARCH" \
#%endif
#%if %with %{cross_compiling}
#buildflags="TARGETCC='$TARGETCC' TARGETCCC='$TARGETCCC' TARGETRANLIB='$TARGETRANLIB' AR='%__ar" CPU_ARCH="$CPU_ARCH"
#%else
#buildflags="TARGETCC='$TARGETCC' TARGETCCC='$TARGETCCC' TARGETRANLIB='$TARGETRANLIB' AR='%__ar"
#%endif
%make -j1 -C ./nss/coreconf
%make -j1 -C ./nss/lib/dbm
%make -j1 -C ./nss

%if %{build_empty}
# tuck away the empty libnssckbi.so library
cp -p nss/lib/ckfw/builtins/Linux*/libnssckbi.so libnssckbi_empty.so
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
libpath=`%{_bindir}/find ./dist/ -name "Linux*.*" -type d`
# to use the built libraries instead of requiring nss
# again as buildrequires
export LD_LIBRARY_PATH="$PWD/$libpath/lib"

pushd nss/lib/ckfw/builtins

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
perl ./certdata.perl /etc/pki/tls/mozilla/certdata.txt

%make clean
%make

popd
export LD_LIBRARY_PATH="$OLD"

%install
pushd dist/$(uname -s)*

mkdir -p %{buildroot}%{_bindir}
cp -aL bin/* %{buildroot}%{_bindir}

%if %with lib
mkdir -p %{buildroot}%{_libdir}
mkdir -p %{buildroot}/%{_lib}
mkdir -p %{buildroot}%{_includedir}/nss
cp -aL ../public/nss/* %{buildroot}%{_includedir}/nss

cp -aL lib/libcrmf.a \
            lib/libnss.a \
            lib/libnssb.a \
            lib/libnssckbi.so \
            lib/libnssckfw.a \
	    lib/libnssutil.a \
            lib/libsmime.a \
            lib/libssl.a \
            %{buildroot}%{_libdir}

# Copy the binary libraries we want
for file in libsoftokn3.so libfreebl3.so libfreeblpriv3.so libnss3.so libnssutil3.so \
            libssl3.so libsmime3.so libnssckbi.so libnssdbm3.so
do
  install -m 755 lib/$file %{buildroot}/%{_lib}
  ln -sf ../../%{_lib}/$file %{buildroot}%{_libdir}/$file
done

# These ghost files will be generated in the post step
# Make sure chk files can be found in both places
for file in libsoftokn3.chk libfreebl3.chk
do
  touch %{buildroot}/%{_lib}/$file
  ln -s ../../%{_lib}/$file %{buildroot}%{_libdir}/$file
done

mkdir -p %{buildroot}%{_libdir}/pkgconfig
cat %{SOURCE2} | sed -e "s,%%libdir%%,%{_libdir},g" \
                          -e "s,%%prefix%%,%{_prefix},g" \
                          -e "s,%%exec_prefix%%,%{_prefix},g" \
                          -e "s,%%includedir%%,%{_includedir}/nss,g" \
                          -e "s,%%NSPR_VERSION%%,%{nspr_version},g" \
                          -e "s,%%NSS_VERSION%%,%{version},g" > \
                          %{buildroot}%{_libdir}/pkgconfig/nss.pc
%endif

popd

%if %with lib
export NSS_VMAJOR=`%{__cat} nss/lib/nss/nss.h | %{__grep} "#define.*NSS_VMAJOR" | %{__awk} '{print $3}'`
export NSS_VMINOR=`%{__cat} nss/lib/nss/nss.h | %{__grep} "#define.*NSS_VMINOR" | %{__awk} '{print $3}'`
export NSS_VPATCH=`echo %{version} | sed 's/\([0-9]*\).\([0-9]*\).\([0-9]*\)/\3/'`

mkdir -p %{buildroot}%{_bindir}
cat %{SOURCE3} | sed -e "s,@libdir@,%{_libdir},g" \
                               -e "s,@prefix@,%{_prefix},g" \
                               -e "s,@exec_prefix@,%{_prefix},g" \
                               -e "s,@includedir@,%{_includedir}/nss%{major},g" \
                               -e "s,@MOD_MAJOR_VERSION@,$NSS_VMAJOR,g" \
                               -e "s,@MOD_MINOR_VERSION@,$NSS_VMINOR,g" \
                               -e "s,@MOD_PATCH_VERSION@,$NSS_VPATCH,g" \
                               > %{buildroot}/%{_bindir}/nss-config
%endif

pushd nss/cmd/smimetools
install -m 0755 smime %{buildroot}%{_bindir}
perl -pi -e 's|/usr/local/bin|%{_bindir}|g' %{buildroot}%{_bindir}/smime
popd

# add docs
mkdir -p docs/SSLsample
#cp -a mozilla/security/nss/cmd/SSLsample/README docs/SSLsample/

mkdir -p docs/bltest
cp -a nss/cmd/bltest/tests/* docs/bltest/
chmod -R a+r docs

mkdir -p docs/certcgi
cp -a nss/cmd/certcgi/*.html docs/certcgi/
cp -a nss/cmd/certcgi/HOWTO.txt docs/certcgi/

mkdir -p docs/modutil
cp -a nss/cmd/modutil/*.html docs/modutil/

mkdir -p docs/signtool
cp -a nss/cmd/signtool/README docs/signtool/

mkdir -p docs/signver
cp -a nss/cmd/signver/examples/1/*.pl docs/signver/
cp -a nss/cmd/signver/examples/1/*.html docs/signver/

mkdir -p docs/ssltap
cp -a nss/cmd/ssltap/*.html docs/ssltap/

# Install the empty NSS db files
mkdir -p %{buildroot}%{_sysconfdir}/pki/nssdb
install -m 644 %{SOURCE4} %{buildroot}%{_sysconfdir}/pki/nssdb/cert8.db
install -m 644 %{SOURCE5} %{buildroot}%{_sysconfdir}/pki/nssdb/key3.db
install -m 644 %{SOURCE6} %{buildroot}%{_sysconfdir}/pki/nssdb/secmod.db

%{_bindir}/find docs -type f | %{_bindir}/xargs -t perl -pi -e 's/\r$//g'

%if %{build_empty}
# install the empty libnssckbi.so library (use alternatives?)
install -m0755 libnssckbi_empty.so %{buildroot}/%{_lib}/libnssckbi_empty.so
%endif

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
%attr(0755,root,root) %{_bindir}/chktest
%attr(0755,root,root) %{_bindir}/cmsutil
%attr(0755,root,root) %{_bindir}/conflict
%attr(0755,root,root) %{_bindir}/crlutil
%attr(0755,root,root) %{_bindir}/crmftest
%attr(0755,root,root) %{_bindir}/dbtest
%attr(0755,root,root) %{_bindir}/derdump
%attr(0755,root,root) %{_bindir}/dertimetest
%attr(0755,root,root) %{_bindir}/digest
%attr(0755,root,root) %{_bindir}/ecperf
%attr(0755,root,root) %{_bindir}/encodeinttest
%attr(0755,root,root) %{_bindir}/fbectest
%attr(0755,root,root) %{_bindir}/fipstest
%attr(0755,root,root) %{_bindir}/httpserv
%attr(0755,root,root) %{_bindir}/listsuites
%attr(0755,root,root) %{_bindir}/lowhashtest
%attr(0755,root,root) %{_bindir}/makepqg
%attr(0755,root,root) %{_bindir}/mangle
%attr(0755,root,root) %{_bindir}/modutil
%attr(0755,root,root) %{_bindir}/multinit
%attr(0755,root,root) %{_bindir}/nonspr10
%attr(0755,root,root) %{_bindir}/ocspclnt
%attr(0755,root,root) %{_bindir}/ocspresp
%attr(0755,root,root) %{_bindir}/oidcalc
%attr(0755,root,root) %{_bindir}/p7content
%attr(0755,root,root) %{_bindir}/p7env
%attr(0755,root,root) %{_bindir}/p7sign
%attr(0755,root,root) %{_bindir}/p7verify
%attr(0755,root,root) %{_bindir}/pk11ectest
%attr(0755,root,root) %{_bindir}/pk11gcmtest
%attr(0755,root,root) %{_bindir}/pk11mode
%attr(0755,root,root) %{_bindir}/pk12util
%attr(0755,root,root) %{_bindir}/pk1sign
%attr(0755,root,root) %{_bindir}/pkix-errcodes
%attr(0755,root,root) %{_bindir}/pp
%attr(0755,root,root) %{_bindir}/pwdecrypt
%attr(0755,root,root) %{_bindir}/remtest
%attr(0755,root,root) %{_bindir}/rsaperf
%attr(0755,root,root) %{_bindir}/sdrtest
%attr(0755,root,root) %{_bindir}/secmodtest
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
/%{_lib}/libfreeblpriv%{major}.so
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

%files -n %{devname}
%attr(0755,root,root) %{_bindir}/nss-config
%_libdir/*.so
%{_includedir}/nss
%{_libdir}/pkgconfig/nss.pc
%{_libdir}/libsoftokn%{major}.chk
%{_libdir}/libfreebl%{major}.chk

%files -n %{sdevname}
%{_libdir}/libcrmf.a
%{_libdir}/libnss.a
%{_libdir}/libnssutil.a
%{_libdir}/libnssb.a
%{_libdir}/libnssckfw.a
%{_libdir}/libsmime.a
%{_libdir}/libssl.a
%endif


%define uversion MAKEFILE_VERSION
Summary: Kernel dropped packet monitor 
Name: dropwatch 
Version: %{uversion} 
Release: 0%{?dist} 
Source0: https://fedorahosted.org/releases/d/r/dropwatch/dropwatch-%{uversion}.tbz2
URL: http://fedorahosted.org/dropwatch
License: GPLv2+ 
Group: Applications/System 
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: kernel-devel, libnl-devel, readline-devel
BuildRequires: binutils-devel, binutils-static
Requires: libnl, readline

%description
dropwatch is an utility to interface to the kernel to monitor for dropped
network packets.

%prep
%setup -q

%build
cd src
export CFLAGS=$RPM_OPT_FLAGS
make 

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_bindir}
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man1
install -m0755 src/dropwatch $RPM_BUILD_ROOT%{_bindir}
install -m0644 doc/dropwatch.1 $RPM_BUILD_ROOT%{_mandir}/man1

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_mandir}/man1/*
%doc README
%doc COPYING

%changelog
* Thu Apr 08 2010 Neil Horman <nhorman@redhat.com> 1.1-0
- Fixing BuildRequires in spec, and removing release variable

* Thu Mar 26 2009 Neil Horman <nhorman@redhat.com> 1.0-3
- Updating Makefile to include release num in tarball

* Fri Mar 20 2009 Neil Horman <nhorman@redhat.com> 1.0-2
- Fixed up Errors found in package review (bz 491240)

* Tue Mar 17 2009 Neil Horman <nhorman@redhat.com> 1.0-1
- Initial build


Summary: Kernel dropped packet monitor 
Name: dropwatch 
Version: MAKEFILE_VERSION 
Release: MAKEFILE_RELEASE%{?dist} 
Source0: https://fedorahosted.org/releases/d/r/dropwatch/dropwatch-%{version}.tbz2
URL: http://fedorahosted.org/dropwatch
License: GPLv2 
Group: Applications/Utilities 
BuildRoot: %{_tmppath}/%{name}-%{version}
BuildRequires: kernel-devel, libnl-devel, readline

%description
dropwatch is an utility to interface to the kernel to monitor for dropped
network packets.

%prep
%setup -q

%build
cd src
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/share/man/man1
install -m0755 src/dropwatch $RPM_BUILD_ROOT/usr/bin
install -m0644 doc/dropwatch.1 $RPM_BUILD_ROOT/usr/share/man/man1

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_mandir}/man1/*
%doc README
%doc COPYING

%changelog
* Tue Mar 17 2009 Neil Horman <nhorman@redhat.com> 1.0-1
- Initial build


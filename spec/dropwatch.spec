Summary: Kernel dropped packet monitor 
Name: dropwatch 
Version: 1.0
Release: 1%{?dist} 
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
cd src

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_mandir}/man1/*

%changelog
Tue Mar 17 2009 Neil Horman <nhorman@redhat.com> 1.0-1
- Initial build


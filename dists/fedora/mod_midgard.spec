%define major_version 8.09.9
%define tar_name midgard-apache2

Name:           mod_midgard
Version:        %{major_version}
Release:        1%{?dist}
Summary:        Midgard module for the Apache HTTP Server

Group:          System Environment/Daemons
License:        GPL+
URL:            http://www.midgard-project.org/
Source0:        %{url}download/%{tar_name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  httpd-devel
BuildRequires:  midgard-core-devel >= %{major_version}

Requires:       httpd-mmn = %(cat %{_includedir}/httpd/.mmn || echo missing)

%description
This package provides Midgard module for the Apache HTTP Server. This 
version makes use of preparsed files in order to reduce the time 
required to respond to requests.

If you intend to use the Midgard Content Management System, install this 
package as it provides the glue between httpd and Midgard.


%prep
%setup -q -n %{tar_name}-%{version}


%build
%configure --with-apxs=%{_sbindir}/apxs
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $(dirname $RPM_BUILD_ROOT)
mkdir $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc COPYING
%{_libdir}/httpd/modules/*


%changelog
* Thu Jul 16 2009 Jarkko Ala-Louvesniemi <jval@puv.fi> 8.09.5-1
- Initial package using the Fedora spec file template.

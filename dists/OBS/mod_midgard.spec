%define major_version 8.10.0
%define tar_name midgard-apache2

%if 0%{?suse_version}
%define httpd apache2
%define apxs apxs2
%define httpd_modulesdir %httpd
%define rpm_name %httpd-mod_midgard
%else
%define httpd httpd
%define apxs apxs
%define httpd_modulesdir %httpd/modules
%define rpm_name mod_midgard
%endif

Name:           %{rpm_name}
Version:        %{major_version}
Release:        OBS
Summary:        Midgard module for the Apache HTTP Server

Group:          System Environment/Daemons
License:        GPL+
URL:            http://www.midgard-project.org/
Source0:        %{url}download/%{tar_name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  %{httpd}-devel
BuildRequires:  midgard-core-devel >= %{major_version}

%if 0%{?suse_version}
Provides:       mod_midgard = %{version}-%{release}
BuildRequires:  rpm
Requires:       %(rpm -q --provides %{httpd} | grep mmn || echo apache_mmn_missing)
%else
Requires:       httpd-mmn = %(cat %{_includedir}/httpd/.mmn || echo missing)
%endif
Obsoletes:      midgard-apache2 < 8.09.6
Provides:       midgard-apache2 = %{version}-%{release}

%description
This package provides Midgard module for the Apache HTTP Server. This 
version makes use of preparsed files in order to reduce the time 
required to respond to requests.

If you intend to use the Midgard Content Management System, install this 
package as it provides the glue between httpd and Midgard.


%prep
%setup -q -n %{tar_name}-%{version}


%build
%configure --with-apxs=%{_sbindir}/%{apxs}
make %{?_smp_mflags}


%install
%if 0%{?suse_version} == 0
rm -rf $RPM_BUILD_ROOT
mkdir -p $(dirname $RPM_BUILD_ROOT)
mkdir $RPM_BUILD_ROOT
%endif
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc COPYING
%{_libdir}/%{httpd_modulesdir}/*


%changelog
* Thu Jul 16 2009 Jarkko Ala-Louvesniemi <jval@puv.fi> 8.09.5
- Initial OBS package based on the Fedora spec.

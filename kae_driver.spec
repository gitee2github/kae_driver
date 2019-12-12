Name: kae_driver
Summary: Kunpeng Accelerator Engine Kernel Driver
Version: 1.2.1
Release: 1
Source: %{name}-%{version}.tar.gz
Vendor: Huawei Corporation
License: GPL-2.0
ExclusiveOS: linux
Group: System Environment/Kernel
Provides: %{name} = %{version}
URL:https://support.huawei.com
BuildRoot: %{_tmppath}/%{name}-%{version}-root

Conflicts: %{name} < %{version}
BuildRequires: kernel-devel, gcc, make

%define kernel_version %(uname -r)

%description
This package contains the Kunpeng Accelerator Engine Kernel Driver

%prep
%global debug_package %{nil}
%setup -c -n %{name}-%{version}

%build
cd kmodules
make


%install
mkdir -p ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -p -m 0644 kmodules/uacce/uacce.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -p -m 0644 kmodules/hisilicon/hisi_qm.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -p -m 0644 kmodules/hisilicon/sec2/hisi_sec2.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -p -m 0644 kmodules/hisilicon/hpre/hisi_hpre.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
mkdir -p ${RPM_BUILD_ROOT}/etc/modprobe.d
install -p -m 0644 kmodules/conf/hisi_sec2.conf ${RPM_BUILD_ROOT}/etc/modprobe.d
install -p -m 0644 kmodules/conf/hisi_hpre.conf ${RPM_BUILD_ROOT}/etc/modprobe.d

%clean
rm -rf ${RPM_BUILD_ROOT}


%files
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/uacce.ko
/lib/modules/%{kernel_version}/extra/hisi_qm.ko
/lib/modules/%{kernel_version}/extra/hisi_sec2.ko
/lib/modules/%{kernel_version}/extra/hisi_hpre.ko

%config(noreplace) /etc/modprobe.d/hisi_sec2.conf
%config(noreplace) /etc/modprobe.d/hisi_hpre.conf

%pre
echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "%{name} modules start to install"
fi

%post
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "%{name} modules installed"

%preun
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "%{name} modules uninstalling"
fi

%postun
if [ "$1" = "0" ] ; then  #0: uninstall
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "%{name} modules uninstalled"

%changelog



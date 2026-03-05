Name:           heimdall
Version:        1.8.0
Release:        1%{?dist}
Summary:        Interactive terminal-based port and process viewer for Linux
License:        MIT
URL:            https://github.com/sunels/heimdall
Source0:        https://github.com/sunels/heimdall/archive/refs/tags/v%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel python3-setuptools
Requires:       python3 python3-psutil iproute procps-ng

%description
Heimdall is a high-performance, curses-based Terminal User Interface (TUI) 
designed to give you instant visibility and control over your Linux system.

%{!?python3_sitelib: %global python3_sitelib %(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

%prep
%autosetup

%build
python3 setup.py build

%install
python3 setup.py install -O1 --root=$RPM_BUILD_ROOT --install-scripts=%{_bindir} --install-lib=%{python3_sitelib}

%files
%license LICENSE
%doc README.md RELEASE_NOTES.md
%{_bindir}/heimdall
%{python3_sitelib}/heimdall/
%{python3_sitelib}/heimdall_linux-*.egg-info/

%changelog
* Thu Mar 05 2026 Serkan Sunel <serkan.sunel@gmail.com> - 1.7.0-1
- Systemd Journal Auditing & Real-time Logs
- Fail-Fast Service Monitoring & Sentinel Log Integration
* Thu Mar 05 2026 Serkan Sunel <serkan.sunel@gmail.com> - 1.5.0-1
- Guardian Mode: Autonomous threat response
- Forensics Vault: Deep incident reports
- SMTP Alerts & Secure configuration
* Tue Mar 03 2026 Serkan Sunel <serkan.sunel@gmail.com> - 1.4.1-1
- Add ZFS, SMART, Fail2Ban, and Firewall plugins
- Refactor plugin system to support command viewers
- UI/UX improvements

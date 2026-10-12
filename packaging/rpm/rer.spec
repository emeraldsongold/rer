%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}
%{!?_docdir: %global _docdir /usr/share/doc}
%global debug_package %{nil}
%global __strip /bin/true
%global __brp_strip %{nil}

Name:           rer
Version:        %{_version}
Release:        1%{?dist}
Summary:        RER Engineering Relay
License:        Apache-2.0
URL:            https://github.com/emeraldsongold/rer

%description
RER Engineering Relay — Open-source network relay, telemetry/command routing,
and distributed network diagnostics tool.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/rer
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}/var/lib/rer
mkdir -p %{buildroot}%{_docdir}/rer

install -m 0755 %{_sourcedir}/rer %{buildroot}%{_bindir}/rer
install -m 0644 %{_sourcedir}/rer.yaml %{buildroot}%{_sysconfdir}/rer/rer.yaml
install -m 0644 %{_sourcedir}/rer.service %{buildroot}%{_unitdir}/rer.service
install -m 0644 %{_sourcedir}/README.md %{buildroot}%{_docdir}/rer/README.md
install -m 0644 %{_sourcedir}/CONFIGURATION.md %{buildroot}%{_docdir}/rer/CONFIGURATION.md

%pre
getent group rer >/dev/null 2>&1 || groupadd -r rer >/dev/null 2>&1 || :
getent passwd rer >/dev/null 2>&1 || useradd -r -g rer -d /var/lib/rer -s /sbin/nologin -c "RER Engineering Relay" rer >/dev/null 2>&1 || :
exit 0

%post
# Systemd unit is NOT enabled or started automatically (safe defaults)
if [ $1 -eq 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    echo "RER package installed successfully with safe defaults."
    echo "Service 'rer.service' is NOT enabled or started automatically."
    echo "Review configuration in %{_sysconfdir}/rer/rer.yaml before starting."
    echo "To enable and start: systemctl enable --now rer"
fi

%preun
if [ $1 -eq 0 ]; then
    # Package removal (not upgrade)
    systemctl stop rer >/dev/null 2>&1 || :
    systemctl disable rer >/dev/null 2>&1 || :
fi

%postun
if [ $1 -ge 1 ]; then
    # Upgrade
    systemctl daemon-reload >/dev/null 2>&1 || :
    echo "RER package upgraded. Existing configuration in %{_sysconfdir}/rer/ preserved."
elif [ $1 -eq 0 ]; then
    # Uninstall: configuration and state preserved (no silent data loss!)
    systemctl daemon-reload >/dev/null 2>&1 || :
    echo "RER package uninstalled."
    echo "Configuration in %{_sysconfdir}/rer/ and state in /var/lib/rer/ have been preserved."
    echo "Remove %{_sysconfdir}/rer and /var/lib/rer manually if complete deletion is intended."
fi

%files
%{_bindir}/rer
%dir %{_sysconfdir}/rer
%config(noreplace) %{_sysconfdir}/rer/rer.yaml
%{_unitdir}/rer.service
%dir %attr(0750, root, root) /var/lib/rer
%doc %{_docdir}/rer/*

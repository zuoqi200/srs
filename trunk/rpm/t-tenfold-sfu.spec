AutoReqProv:no
Summary: tenfold sfu
Name: t-tenfold-sfu
Version: 1.0.0
Release: %(echo $RELEASE)%{?dist}
License: Commercial
Group: Applications/Server
Source: tenfold-sfu.tar.gz
BuildRoot: /tmp/tenfold-sfu-build-root
Distribution: Linux
Packager:jixue.cgh

%define tf_prefix /home/admin/tenfold-sfu

%description
Tenfold Selective Forwarding Unit

%define _builddir		.
%define _rpmdir			.
%define __os_install_post 	/usr/lib/rpm/brp-compress; echo 'Not stripping.'

%prep

%build
echo "Start to build tenfold sfu in docker..."
pushd $OLDPWD/../

# PUSH the release variable, for tenfold use it in build script.
OLD_RELEASE=${RELEASE}
RELEASE=""

./configure --static --prefix=%{tf_prefix} && make

RELEASE=${OLD_RELEASE}
OLD_RELEASE=""

popd

%install
pushd $OLDPWD/../
rm -rf $RPM_BUILD_ROOT
PREFIX=$RPM_BUILD_ROOT
make DESTDIR=${PREFIX} install-tenfold-sfu
popd

%clean
rm -rf $RPM_BUILD_ROOT

%pre

%post
systemctl enable tenfold-sfu.service


%preun
if [ "$1" == "0" ]; then
	# Add || : to exit zero for errors.
	# See more @https://fedoraproject.org/wiki/Packaging:Scriptlets
	systemctl disable tenfold-sfu.service || echo "failed to unregister"
fi

%postun

%files
%defattr(755, admin, admin, -)
/home/admin/tenfold-sfu/objs
/home/admin/tenfold-sfu/logs
/home/admin/tenfold-sfu/objs/nginx
/home/admin/tenfold-sfu/objs/nginx/html
/home/admin/tenfold-sfu/objs/tf_sfu
/home/admin/tenfold-sfu/objs/tf_sfu_ctl.sh
/home/admin/tenfold-sfu/objs/tf_supervise_ctl.sh
/home/admin/tenfold-sfu/objs/tf_master_ctl.sh
/home/admin/tenfold-sfu/objs/tf_sfu_auto_launch.sh
/etc/logrotate.d/tenfold_sfu.conf
%attr(644, root, root)/usr/lib/systemd/system/tenfold_sfu.service

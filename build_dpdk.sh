cd /data/f-stack/dpdk
meson -Denable_kmods=true -Ddisable_libs=flow_classify build
ninja -C build
ninja -C build install
	
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

echo 0 > /proc/sys/kernel/randomize_va_space

export myaddr=`ifconfig ens34 | grep "inet" | grep -v ":" | awk -F ' '  '{print $2}'`
export mymask=`ifconfig ens34 | grep "netmask" | awk -F ' ' '{print $4}'`
export mybc=`ifconfig ens34 | grep "broadcast" | awk -F ' ' '{print $6}'`
export myhw=`ifconfig ens34 | grep "ether" | awk -F ' ' '{print $2}'`
export mygw=`route -n | grep 0.0.0.0 | grep ens34 | grep UG | awk -F ' ' '{print $2}'`

sed "s/addr=192.168.1.2/addr=${myaddr}/" -i /data/f-stack/config.ini
sed "s/netmask=255.255.255.0/netmask=${mymask}/" -i /data/f-stack/config.ini
sed "s/broadcast=192.168.1.255/broadcast=${mybc}/" -i /data/f-stack/config.ini
sed "s/gateway=192.168.1.1/gateway=${mygw}/" -i /data/f-stack/config.ini

sed "s/#\[kni\]/\[kni\]/" -i /data/f-stack/config.ini
sed "s/#enable=1/enable=1/" -i /data/f-stack/config.ini
sed "s/#method=reject/method=reject/" -i /data/f-stack/config.ini
sed "s/#tcp_port=80/tcp_port=80/" -i /data/f-stack/config.ini
sed "s/#vlanstrip=1/vlanstrip=1/" -i /data/f-stack/config.ini

modprobe uio
modprobe hwmon
insmod /data/f-stack/dpdk/build/kernel/linux/igb_uio/igb_uio.ko
insmod /data/f-stack/dpdk/build/kernel/linux/kni/rte_kni.ko carrier=on

cd /data/pkg-config-0.29.2/ 
./configure --with-internal-glib
make
make install
mv /usr/bin/pkg-config /usr/bin/pkg-config.bak
ln -s /usr/local/bin/pkg-config /usr/bin/pkg-config

export FF_PATH=/data/f-stack
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig
cd /data/f-stack/lib
make
make install

cd ../app/nginx-1.25.2
./configure --prefix=/usr/local/nginx_fstack --with-ff_module --without-http_rewrite_module 
make
make install

nr_ens34=$(/data/f-stack/dpdk/usertools/dpdk-devbind.py --status | grep ens34 | cut -c 1-12)
ifconfig ens34 down
/data/f-stack/dpdk/usertools/dpdk-devbind.py --bind=igb_uio "$nr_ens34"
bind_result=$(/data/f-stack/dpdk/usertools/dpdk-devbind.py --status | grep "$nr_ens34")
echo "$bind_result"

cp /data/f-stack/config.ini /usr/local/nginx_fstack/conf/f-stack.conf

# /usr/local/nginx_fstack/sbin/nginx

ifconfig ens34 ${myaddr}  netmask ${mymask}  broadcast ${mybc} hw ether ${myhw}
route add -net 0.0.0.0 gw ${mygw} dev ens34
echo 1 > /sys/class/net/ens34/carrier

cd /data/f-stack/app/redis-6.2.6/deps/jemalloc 
./autogen.sh
cd /data/f-stack/app/redis-6.2.6  
make

cd /data/f-stack/tools 
make

cd /data/f-stack/example 
make


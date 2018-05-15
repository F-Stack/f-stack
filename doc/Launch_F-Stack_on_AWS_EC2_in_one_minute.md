# Launch F-Stack on AWS EC2 in one minute

  If you have a Redhat7.3 EC2 instance，and then execute the following cmds, you will get the F-Stack server in one minute 

    sudo -i
    yum install -y git gcc openssl-devel kernel-devel-$(uname -r) bc numactl-devel

    mkdir /data/f-stack
    git clone https://github.com/F-Stack/f-stack.git /data/f-stack

    # Compile DPDK
    cd /data/f-stack/dpdk
    make config T=x86_64-native-linuxapp-gcc
    make

    # set hugepage	
    echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
    mkdir /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge

    # close ASLR; it is necessary in multiple process
    echo 0 > /proc/sys/kernel/randomize_va_space

    # insmod ko
    modprobe uio
    modprobe hwmon
    insmod build/kmod/igb_uio.ko
    insmod build/kmod/rte_kni.ko

    # set ip address
    #redhat7.3
    export myaddr=`ifconfig eth0 | grep "inet" | grep -v ":" | awk -F ' '  '{print $2}'`
    export mymask=`ifconfig eth0 | grep "netmask" | awk -F ' ' '{print $4}'`
    export mybc=`ifconfig eth0 | grep "broadcast" | awk -F ' ' '{print $6}'`
    export myhw=`ifconfig eth0 | grep "ether" | awk -F ' ' '{print $2}'`
    export mygw=`route -n | grep 0.0.0.0 | grep eth0 | grep UG | awk -F ' ' '{print $2}'`
    #Amazon Linux AMI 2017.03
    #export myaddr=`ifconfig eth0 | grep "inet addr" | awk -F ' '  '{print $2}' |  awk -F ':' '{print $2}'`
    #export mymask=`ifconfig eth0 | grep "Mask" | awk -F ' ' '{print $4}' |  awk -F ':' '{print $2}'`
    #export mybc=`ifconfig eth0 | grep "Bcast" | awk -F ' ' '{print $3}' |  awk -F ':' '{print $2}'`
    #export myhw=`ifconfig eth0 | grep "HWaddr" | awk -F ' ' '{print $5}'`
    #export mygw=`route -n | grep 0.0.0.0 | grep eth0 | grep UG | awk -F ' ' '{print $2}'

    sed "s/addr=192.168.1.2/addr=${myaddr}/" -i /data/f-stack/config.ini
    sed "s/netmask=255.255.255.0/netmask=${mymask}/" -i /data/f-stack/config.ini
    sed "s/broadcast=192.168.1.255/broadcast=${mybc}/" -i /data/f-stack/config.ini
    sed "s/gateway=192.168.1.1/gateway=${mygw}/" -i /data/f-stack/config.ini

    # enable kni
    sed "s/#\[kni\]/\[kni\]/" -i /data/f-stack/config.ini
    sed "s/#enable=1/enable=1/" -i /data/f-stack/config.ini
    sed "s/#method=reject/method=reject/" -i /data/f-stack/config.ini
    sed "s/#tcp_port=80/tcp_port=80/" -i /data/f-stack/config.ini
    sed "s/#vlanstrip=1/vlanstrip=1/" -i /data/f-stack/config.ini

    # Compile F-Stack lib
    export FF_PATH=/data/f-stack
    export FF_DPDK=/data/f-stack/dpdk/build
    cd /data/f-stack/lib
    make

    # Compile Nginx
    cd ../app/nginx-1.11.10
    ./configure --prefix=/usr/local/nginx_fstack --with-ff_module
    make
    make install

    # offload NIC（if there is only one NIC，the follow commands must run in a script）
    ifconfig eth0 down
    python /data/f-stack/dpdk/usertools/dpdk-devbind.py --bind=igb_uio eth0

    # copy config.ini to $NGX_PREFIX/conf/f-stack.conf
    cp /data/f-stack/config.ini /usr/local/nginx_fstack/conf/f-stack.conf

    # start Nginx
    /usr/local/nginx_fstack/sbin/nginx

    # start kni
    sleep 10
    ifconfig veth0 ${myaddr}  netmask ${mymask}  broadcast ${mybc} hw ether ${myhw}
    route add -net 0.0.0.0 gw ${mygw} dev veth0

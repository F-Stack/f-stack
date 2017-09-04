#!/bin/bash

function usage() {
    echo "F-Stack app start tool"
    echo "Options:"
    echo " -c [conf]                Path of config file"
    echo " -b [N]                   Path of binary"
    echo " -o [N]                   Other ARGs for app"
    echo " -h                       show this help"
    exit
}

conf=config.ini
bin=./example/helloworld

while getopts "c:b:o:h" args
do
    case $args in
         c)
            conf=$OPTARG
            ;;
         b)
            bin=$OPTARG
            ;;
         o)
            others=$OPTARG
            ;;
         h)
            usage
            exit 0
            ;;
    esac
done

if ! type "bc" > /dev/null 2>&1; then
    echo "please install bc"
    exit
fi

allcmask0x=`cat ${conf}|grep lcore_mask|awk -F '=' '{print $2}'`
((allcmask=16#$allcmask0x))

num_procs=0
PROCESSOR=$(grep 'processor' /proc/cpuinfo |sort |uniq |wc -l)
for((i=0;i<${PROCESSOR};++i))
do
    mask=`echo "2^$i"|bc`
    ((result=${allcmask} & ${mask}))
    if [ ${result} != 0 ]
    then
        ((num_procs++));
    fi
done

for((proc_id=0; proc_id<${num_procs}; ++proc_id))
do
    if ((proc_id == 0))
    then
        echo "${bin} --conf ${conf} --proc-type=primary --proc-id=${proc_id} ${others}"
        ${bin} --conf ${conf} --proc-type=primary --proc-id=${proc_id} ${others} &
        sleep 5
    else
        echo "${bin} --conf ${conf} --proc-type=secondary --proc-id=${proc_id} ${others}"
        ${bin} --conf ${conf} --proc-type=secondary --proc-id=${proc_id} ${others} &
    fi
done

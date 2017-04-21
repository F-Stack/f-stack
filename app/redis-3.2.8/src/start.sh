#!/bin/bash

function usage() {
    echo "F-Stack app start tool"
    echo "Options:"
    echo " -c [conf]                Path of config file"
    echo " -b [N]                   Path of binary"
    echo " -h                       show this help"
    exit
}

conf=./config.ini
bin=./redis-server

while getopts "c:b:h" args
do
    case $args in
         c)
            conf=$OPTARG
            ;;
         b)
            bin=$OPTARG
            ;;
         h)
            usage
            exit 0
            ;;
    esac
done

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
        cpuinfo[$i]=1
    else
        cpuinfo[$i]=0
    fi
done

proc_id=0
for((i=0;i<${PROCESSOR};++i))
do
    if ((cpuinfo[$i] == 1))
    then
        cmask=`echo "2^$i"|bc`
        cmask=`echo "obase=16;${cmask}"|bc`
        if ((proc_id == 0))
        then
            echo "${bin} ${conf} -c $cmask --proc-type=primary --num-procs=${num_procs} --proc-id=${proc_id}"
            ${bin} ${conf} -c ${cmask} --proc-type=primary --num-procs=${num_procs} --proc-id=${proc_id} ../redis.conf &
            sleep 5
        else
            echo "${bin} ${conf} -c $cmask --proc-type=secondary --num-procs=${num_procs} --proc-id=${proc_id}"
			${bin} ${conf} -c $cmask --proc-type=secondary --num-procs=${num_procs} --proc-id=${proc_id} ../redis.conf &
        fi
        ((proc_id++))
    fi 
done

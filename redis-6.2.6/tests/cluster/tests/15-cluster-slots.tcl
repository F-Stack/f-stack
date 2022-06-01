source "../tests/includes/init-tests.tcl"

proc cluster_allocate_mixedSlots {n} {
    set slot 16383
    while {$slot >= 0} {
        set node [expr {$slot % $n}]
        lappend slots_$node $slot
        incr slot -1
    }
    for {set j 0} {$j < $n} {incr j} {
        R $j cluster addslots {*}[set slots_${j}]
    }
}

proc create_cluster_with_mixedSlot {masters slaves} {
    cluster_allocate_mixedSlots $masters
    if {$slaves} {
        cluster_allocate_slaves $masters $slaves
    }
    assert_cluster_state ok
}

test "Create a 5 nodes cluster" {
    create_cluster_with_mixedSlot 5 15
}

test "Cluster is up" {
    assert_cluster_state ok
}

test "Cluster is writable" {
    cluster_write_test 0
}

test "Instance #5 is a slave" {
    assert {[RI 5 role] eq {slave}}
}

test "client do not break when cluster slot" {
    R 0 config set client-output-buffer-limit "normal 33554432 16777216 60"
    if { [catch {R 0 cluster slots}] } {
        fail "output overflow when cluster slots"
    }
}

test "client can handle keys with hash tag" {
    set cluster [redis_cluster 127.0.0.1:[get_instance_attrib redis 0 port]]
    $cluster set foo{tag} bar
    $cluster close
}

if {$::tls} {
    test {CLUSTER SLOTS from non-TLS client in TLS cluster} {
        set slots_tls [R 0 cluster slots]
        set host [get_instance_attrib redis 0 host]
        set plaintext_port [get_instance_attrib redis 0 plaintext-port]
        set client_plain [redis $host $plaintext_port 0 0]
        set slots_plain [$client_plain cluster slots]
        $client_plain close
        # Compare the ports in the first row
        assert_no_match [lindex $slots_tls 0 3 1] [lindex $slots_plain 0 3 1]
    }
}

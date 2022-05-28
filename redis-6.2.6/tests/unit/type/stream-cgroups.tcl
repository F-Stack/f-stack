start_server {
    tags {"stream"}
} {
    test {XGROUP CREATE: creation and duplicate group name detection} {
        r DEL mystream
        r XADD mystream * foo bar
        r XGROUP CREATE mystream mygroup $
        catch {r XGROUP CREATE mystream mygroup $} err
        set err
    } {BUSYGROUP*}

    test {XGROUP CREATE: automatic stream creation fails without MKSTREAM} {
        r DEL mystream
        catch {r XGROUP CREATE mystream mygroup $} err
        set err
    } {ERR*}

    test {XGROUP CREATE: automatic stream creation works with MKSTREAM} {
        r DEL mystream
        r XGROUP CREATE mystream mygroup $ MKSTREAM
    } {OK}

    test {XREADGROUP will return only new elements} {
        r XADD mystream * a 1
        r XADD mystream * b 2
        # XREADGROUP should return only the new elements "a 1" "b 1"
        # and not the element "foo bar" which was pre existing in the
        # stream (see previous test)
        set reply [
            r XREADGROUP GROUP mygroup consumer-1 STREAMS mystream ">"
        ]
        assert {[llength [lindex $reply 0 1]] == 2}
        lindex $reply 0 1 0 1
    } {a 1}

    test {XREADGROUP can read the history of the elements we own} {
        # Add a few more elements
        r XADD mystream * c 3
        r XADD mystream * d 4
        # Read a few elements using a different consumer name
        set reply [
            r XREADGROUP GROUP mygroup consumer-2 STREAMS mystream ">"
        ]
        assert {[llength [lindex $reply 0 1]] == 2}
        assert {[lindex $reply 0 1 0 1] eq {c 3}}

        set r1 [r XREADGROUP GROUP mygroup consumer-1 COUNT 10 STREAMS mystream 0]
        set r2 [r XREADGROUP GROUP mygroup consumer-2 COUNT 10 STREAMS mystream 0]
        assert {[lindex $r1 0 1 0 1] eq {a 1}}
        assert {[lindex $r2 0 1 0 1] eq {c 3}}
    }

    test {XPENDING is able to return pending items} {
        set pending [r XPENDING mystream mygroup - + 10]
        assert {[llength $pending] == 4}
        for {set j 0} {$j < 4} {incr j} {
            set item [lindex $pending $j]
            if {$j < 2} {
                set owner consumer-1
            } else {
                set owner consumer-2
            }
            assert {[lindex $item 1] eq $owner}
            assert {[lindex $item 1] eq $owner}
        }
    }

    test {XPENDING can return single consumer items} {
        set pending [r XPENDING mystream mygroup - + 10 consumer-1]
        assert {[llength $pending] == 2}
    }

    test {XPENDING only group} {
        set pending [r XPENDING mystream mygroup]
        assert {[llength $pending] == 4}
    }

    test {XPENDING with IDLE} {
        after 20
        set pending [r XPENDING mystream mygroup IDLE 99999999 - + 10 consumer-1]
        assert {[llength $pending] == 0}
        set pending [r XPENDING mystream mygroup IDLE 1 - + 10 consumer-1]
        assert {[llength $pending] == 2}
        set pending [r XPENDING mystream mygroup IDLE 99999999 - + 10]
        assert {[llength $pending] == 0}
        set pending [r XPENDING mystream mygroup IDLE 1 - + 10]
        assert {[llength $pending] == 4}
    }

    test {XPENDING with exclusive range intervals works as expected} {
        set pending [r XPENDING mystream mygroup - + 10]
        assert {[llength $pending] == 4}
        set startid [lindex [lindex $pending 0] 0]
        set endid [lindex [lindex $pending 3] 0]
        set expending [r XPENDING mystream mygroup ($startid ($endid 10]
        assert {[llength $expending] == 2}
        for {set j 0} {$j < 2} {incr j} {
            set itemid [lindex [lindex $expending $j] 0]
            assert {$itemid ne $startid}
            assert {$itemid ne $endid}
        }
    }

    test {XACK is able to remove items from the consumer/group PEL} {
        set pending [r XPENDING mystream mygroup - + 10 consumer-1]
        set id1 [lindex $pending 0 0]
        set id2 [lindex $pending 1 0]
        assert {[r XACK mystream mygroup $id1] eq 1}
        set pending [r XPENDING mystream mygroup - + 10 consumer-1]
        assert {[llength $pending] == 1}
        set id [lindex $pending 0 0]
        assert {$id eq $id2}
        set global_pel [r XPENDING mystream mygroup - + 10]
        assert {[llength $global_pel] == 3}
    }

    test {XACK can't remove the same item multiple times} {
        assert {[r XACK mystream mygroup $id1] eq 0}
    }

    test {XACK is able to accept multiple arguments} {
        # One of the IDs was already removed, so it should ack
        # just ID2.
        assert {[r XACK mystream mygroup $id1 $id2] eq 1}
    }

    test {XACK should fail if got at least one invalid ID} {
        r del mystream
        r xgroup create s g $ MKSTREAM
        r xadd s * f1 v1
        set c [llength [lindex [r xreadgroup group g c streams s >] 0 1]]
        assert {$c == 1}
        set pending [r xpending s g - + 10 c]
        set id1 [lindex $pending 0 0]
        assert_error "*Invalid stream ID specified*" {r xack s g $id1 invalid-id}
        assert {[r xack s g $id1] eq 1}
    }

    test {PEL NACK reassignment after XGROUP SETID event} {
        r del events
        r xadd events * f1 v1
        r xadd events * f1 v1
        r xadd events * f1 v1
        r xadd events * f1 v1
        r xgroup create events g1 $
        r xadd events * f1 v1
        set c [llength [lindex [r xreadgroup group g1 c1 streams events >] 0 1]]
        assert {$c == 1}
        r xgroup setid events g1 -
        set c [llength [lindex [r xreadgroup group g1 c2 streams events >] 0 1]]
        assert {$c == 5}
    }

    test {XREADGROUP will not report data on empty history. Bug #5577} {
        r del events
        r xadd events * a 1
        r xadd events * b 2
        r xadd events * c 3
        r xgroup create events mygroup 0

        # Current local PEL should be empty
        set res [r xpending events mygroup - + 10]
        assert {[llength $res] == 0}

        # So XREADGROUP should read an empty history as well
        set res [r xreadgroup group mygroup myconsumer count 3 streams events 0]
        assert {[llength [lindex $res 0 1]] == 0}

        # We should fetch all the elements in the stream asking for >
        set res [r xreadgroup group mygroup myconsumer count 3 streams events >]
        assert {[llength [lindex $res 0 1]] == 3}

        # Now the history is populated with three not acked entries
        set res [r xreadgroup group mygroup myconsumer count 3 streams events 0]
        assert {[llength [lindex $res 0 1]] == 3}
    }

    test {XREADGROUP history reporting of deleted entries. Bug #5570} {
        r del mystream
        r XGROUP CREATE mystream mygroup $ MKSTREAM
        r XADD mystream 1 field1 A
        r XREADGROUP GROUP mygroup myconsumer STREAMS mystream >
        r XADD mystream MAXLEN 1 2 field1 B
        r XREADGROUP GROUP mygroup myconsumer STREAMS mystream >

        # Now we have two pending entries, however one should be deleted
        # and one should be ok (we should only see "B")
        set res [r XREADGROUP GROUP mygroup myconsumer STREAMS mystream 0-1]
        assert {[lindex $res 0 1 0] == {1-0 {}}}
        assert {[lindex $res 0 1 1] == {2-0 {field1 B}}}
    }

    test {Blocking XREADGROUP will not reply with an empty array} {
        r del mystream
        r XGROUP CREATE mystream mygroup $ MKSTREAM
        r XADD mystream 666 f v
        set res [r XREADGROUP GROUP mygroup Alice BLOCK 10 STREAMS mystream ">"]
        assert {[lindex $res 0 1 0] == {666-0 {f v}}}
        r XADD mystream 667 f2 v2
        r XDEL mystream 667
        set rd [redis_deferring_client]
        $rd XREADGROUP GROUP mygroup Alice BLOCK 10 STREAMS mystream ">"
        after 20
        assert {[$rd read] == {}} ;# before the fix, client didn't even block, but was served synchronously with {mystream {}}
    }

    test {XGROUP DESTROY should unblock XREADGROUP with -NOGROUP} {
        r del mystream
        r XGROUP CREATE mystream mygroup $ MKSTREAM
        set rd [redis_deferring_client]
        $rd XREADGROUP GROUP mygroup Alice BLOCK 100 STREAMS mystream ">"
        r XGROUP DESTROY mystream mygroup
        assert_error "*NOGROUP*" {$rd read}
    }

    test {RENAME can unblock XREADGROUP with data} {
        r del mystream
        r XGROUP CREATE mystream mygroup $ MKSTREAM
        set rd [redis_deferring_client]
        $rd XREADGROUP GROUP mygroup Alice BLOCK 0 STREAMS mystream ">"
        r XGROUP CREATE mystream2 mygroup $ MKSTREAM
        r XADD mystream2 100 f1 v1
        r RENAME mystream2 mystream
        assert_equal "{mystream {{100-0 {f1 v1}}}}" [$rd read] ;# mystream2 had mygroup before RENAME
    }

    test {RENAME can unblock XREADGROUP with -NOGROUP} {
        r del mystream
        r XGROUP CREATE mystream mygroup $ MKSTREAM
        set rd [redis_deferring_client]
        $rd XREADGROUP GROUP mygroup Alice BLOCK 0 STREAMS mystream ">"
        r XADD mystream2 100 f1 v1
        r RENAME mystream2 mystream
        assert_error "*NOGROUP*" {$rd read} ;# mystream2 didn't have mygroup before RENAME
    }

    test {XCLAIM can claim PEL items from another consumer} {
        # Add 3 items into the stream, and create a consumer group
        r del mystream
        set id1 [r XADD mystream * a 1]
        set id2 [r XADD mystream * b 2]
        set id3 [r XADD mystream * c 3]
        r XGROUP CREATE mystream mygroup 0

        # Consumer 1 reads item 1 from the stream without acknowledgements.
        # Consumer 2 then claims pending item 1 from the PEL of consumer 1
        set reply [
            r XREADGROUP GROUP mygroup consumer1 count 1 STREAMS mystream >
        ]
        assert {[llength [lindex $reply 0 1 0 1]] == 2}
        assert {[lindex $reply 0 1 0 1] eq {a 1}}

        # make sure the entry is present in both the gorup, and the right consumer
        assert {[llength [r XPENDING mystream mygroup - + 10]] == 1}
        assert {[llength [r XPENDING mystream mygroup - + 10 consumer1]] == 1}
        assert {[llength [r XPENDING mystream mygroup - + 10 consumer2]] == 0}

        after 200
        set reply [
            r XCLAIM mystream mygroup consumer2 10 $id1
        ]
        assert {[llength [lindex $reply 0 1]] == 2}
        assert {[lindex $reply 0 1] eq {a 1}}

        # make sure the entry is present in both the gorup, and the right consumer
        assert {[llength [r XPENDING mystream mygroup - + 10]] == 1}
        assert {[llength [r XPENDING mystream mygroup - + 10 consumer1]] == 0}
        assert {[llength [r XPENDING mystream mygroup - + 10 consumer2]] == 1}

        # Consumer 1 reads another 2 items from stream
        r XREADGROUP GROUP mygroup consumer1 count 2 STREAMS mystream >
        after 200

        # Delete item 2 from the stream. Now consumer 1 has PEL that contains
        # only item 3. Try to use consumer 2 to claim the deleted item 2
        # from the PEL of consumer 1, this should return nil
        r XDEL mystream $id2
        set reply [
            r XCLAIM mystream mygroup consumer2 10 $id2
        ]
        assert {[llength $reply] == 1}
        assert_equal "" [lindex $reply 0]

        # Delete item 3 from the stream. Now consumer 1 has PEL that is empty.
        # Try to use consumer 2 to claim the deleted item 3 from the PEL
        # of consumer 1, this should return nil
        after 200
        r XDEL mystream $id3
        set reply [
            r XCLAIM mystream mygroup consumer2 10 $id3
        ]
        assert {[llength $reply] == 1}
        assert_equal "" [lindex $reply 0]
    }

    test {XCLAIM without JUSTID increments delivery count} {
        # Add 3 items into the stream, and create a consumer group
        r del mystream
        set id1 [r XADD mystream * a 1]
        set id2 [r XADD mystream * b 2]
        set id3 [r XADD mystream * c 3]
        r XGROUP CREATE mystream mygroup 0

        # Consumer 1 reads item 1 from the stream without acknowledgements.
        # Consumer 2 then claims pending item 1 from the PEL of consumer 1
        set reply [
            r XREADGROUP GROUP mygroup consumer1 count 1 STREAMS mystream >
        ]
        assert {[llength [lindex $reply 0 1 0 1]] == 2}
        assert {[lindex $reply 0 1 0 1] eq {a 1}}
        after 200
        set reply [
            r XCLAIM mystream mygroup consumer2 10 $id1
        ]
        assert {[llength [lindex $reply 0 1]] == 2}
        assert {[lindex $reply 0 1] eq {a 1}}

        set reply [
            r XPENDING mystream mygroup - + 10
        ]
        assert {[llength [lindex $reply 0]] == 4}
        assert {[lindex $reply 0 3] == 2}

        # Consumer 3 then claims pending item 1 from the PEL of consumer 2 using JUSTID
        after 200
        set reply [
            r XCLAIM mystream mygroup consumer3 10 $id1 JUSTID
        ]
        assert {[llength $reply] == 1}
        assert {[lindex $reply 0] eq $id1}

        set reply [
            r XPENDING mystream mygroup - + 10
        ]
        assert {[llength [lindex $reply 0]] == 4}
        assert {[lindex $reply 0 3] == 2}
    }

    test {XCLAIM same consumer} {
        # Add 3 items into the stream, and create a consumer group
        r del mystream
        set id1 [r XADD mystream * a 1]
        set id2 [r XADD mystream * b 2]
        set id3 [r XADD mystream * c 3]
        r XGROUP CREATE mystream mygroup 0

        set reply [r XREADGROUP GROUP mygroup consumer1 count 1 STREAMS mystream >]
        assert {[llength [lindex $reply 0 1 0 1]] == 2}
        assert {[lindex $reply 0 1 0 1] eq {a 1}}
        after 200
        # re-claim with the same consumer that already has it
        assert {[llength [r XCLAIM mystream mygroup consumer1 10 $id1]] == 1}

        # make sure the entry is still in the PEL
        set reply [r XPENDING mystream mygroup - + 10]
        assert {[llength $reply] == 1}
        assert {[lindex $reply 0 1] eq {consumer1}}
    }

    test {XAUTOCLAIM can claim PEL items from another consumer} {
        # Add 3 items into the stream, and create a consumer group
        r del mystream
        set id1 [r XADD mystream * a 1]
        set id2 [r XADD mystream * b 2]
        set id3 [r XADD mystream * c 3]
        r XGROUP CREATE mystream mygroup 0

        # Consumer 1 reads item 1 from the stream without acknowledgements.
        # Consumer 2 then claims pending item 1 from the PEL of consumer 1
        set reply [r XREADGROUP GROUP mygroup consumer1 count 1 STREAMS mystream >]
        assert_equal [llength [lindex $reply 0 1 0 1]] 2
        assert_equal [lindex $reply 0 1 0 1] {a 1}
        after 200
        set reply [r XAUTOCLAIM mystream mygroup consumer2 10 - COUNT 1]
        assert_equal [llength $reply] 2
        assert_equal [lindex $reply 0] "0-0"
        assert_equal [llength [lindex $reply 1]] 1
        assert_equal [llength [lindex $reply 1 0]] 2
        assert_equal [llength [lindex $reply 1 0 1]] 2
        assert_equal [lindex $reply 1 0 1] {a 1}

        # Consumer 1 reads another 2 items from stream
        r XREADGROUP GROUP mygroup consumer1 count 2 STREAMS mystream >

        # For min-idle-time
        after 200

        # Delete item 2 from the stream. Now consumer 1 has PEL that contains
        # only item 3. Try to use consumer 2 to claim the deleted item 2
        # from the PEL of consumer 1, this should return nil
        r XDEL mystream $id2
        set reply [r XAUTOCLAIM mystream mygroup consumer2 10 - COUNT 2]
        # id1 is self-claimed here but not id2 ('count' was set to 2)
        assert_equal [llength $reply] 2
        assert_equal [lindex $reply 0] $id3
        assert_equal [llength [lindex $reply 1]] 2
        assert_equal [llength [lindex $reply 1 0]] 2
        assert_equal [llength [lindex $reply 1 0 1]] 2
        assert_equal [lindex $reply 1 0 1] {a 1}
        assert_equal [lindex $reply 1 1] ""

        # Delete item 3 from the stream. Now consumer 1 has PEL that is empty.
        # Try to use consumer 2 to claim the deleted item 3 from the PEL
        # of consumer 1, this should return nil
        after 200
        r XDEL mystream $id3
        set reply [r XAUTOCLAIM mystream mygroup consumer2 10 - JUSTID]
        # id1 is self-claimed here but not id2 and id3 ('count' is default 100)

        # we also test the JUSTID modifier here. note that, when using JUSTID,
        # deleted entries are returned in reply (consistent with XCLAIM).

        assert_equal [llength $reply] 2
        assert_equal [lindex $reply 0] "0-0"
        assert_equal [llength [lindex $reply 1]] 3
        assert_equal [lindex $reply 1 0] $id1
        assert_equal [lindex $reply 1 1] $id2
        assert_equal [lindex $reply 1 2] $id3
    }

    test {XAUTOCLAIM as an iterator} {
        # Add 5 items into the stream, and create a consumer group
        r del mystream
        set id1 [r XADD mystream * a 1]
        set id2 [r XADD mystream * b 2]
        set id3 [r XADD mystream * c 3]
        set id4 [r XADD mystream * d 4]
        set id5 [r XADD mystream * e 5]
        r XGROUP CREATE mystream mygroup 0

        # Read 5 messages into consumer1
        r XREADGROUP GROUP mygroup consumer1 count 90 STREAMS mystream >

        # For min-idle-time
        after 200

        # Claim 2 entries
        set reply [r XAUTOCLAIM mystream mygroup consumer2 10 - COUNT 2]
        assert_equal [llength $reply] 2
        set cursor [lindex $reply 0]
        assert_equal $cursor $id3
        assert_equal [llength [lindex $reply 1]] 2
        assert_equal [llength [lindex $reply 1 0 1]] 2
        assert_equal [lindex $reply 1 0 1] {a 1}

        # Claim 2 more entries
        set reply [r XAUTOCLAIM mystream mygroup consumer2 10 $cursor COUNT 2]
        assert_equal [llength $reply] 2
        set cursor [lindex $reply 0]
        assert_equal $cursor $id5
        assert_equal [llength [lindex $reply 1]] 2
        assert_equal [llength [lindex $reply 1 0 1]] 2
        assert_equal [lindex $reply 1 0 1] {c 3}

        # Claim last entry
        set reply [r XAUTOCLAIM mystream mygroup consumer2 10 $cursor COUNT 1]
        assert_equal [llength $reply] 2
        set cursor [lindex $reply 0]
        assert_equal $cursor {0-0}
        assert_equal [llength [lindex $reply 1]] 1
        assert_equal [llength [lindex $reply 1 0 1]] 2
        assert_equal [lindex $reply 1 0 1] {e 5}
    }

    test {XAUTOCLAIM COUNT must be > 0} {
       assert_error "ERR COUNT must be > 0" {r XAUTOCLAIM key group consumer 1 1 COUNT 0}
    }

    test {XINFO FULL output} {
        r del x
        r XADD x 100 a 1
        r XADD x 101 b 1
        r XADD x 102 c 1
        r XADD x 103 e 1
        r XADD x 104 f 1
        r XGROUP CREATE x g1 0
        r XGROUP CREATE x g2 0
        r XREADGROUP GROUP g1 Alice COUNT 1 STREAMS x >
        r XREADGROUP GROUP g1 Bob COUNT 1 STREAMS x >
        r XREADGROUP GROUP g1 Bob NOACK COUNT 1 STREAMS x >
        r XREADGROUP GROUP g2 Charlie COUNT 4 STREAMS x >
        r XDEL x 103

        set reply [r XINFO STREAM x FULL]
        assert_equal [llength $reply] 12
        assert_equal [lindex $reply 1] 4 ;# stream length
        assert_equal [lindex $reply 9] "{100-0 {a 1}} {101-0 {b 1}} {102-0 {c 1}} {104-0 {f 1}}" ;# entries
        assert_equal [lindex $reply 11 0 1] "g1" ;# first group name
        assert_equal [lindex $reply 11 0 7 0 0] "100-0" ;# first entry in group's PEL
        assert_equal [lindex $reply 11 0 9 0 1] "Alice" ;# first consumer
        assert_equal [lindex $reply 11 0 9 0 7 0 0] "100-0" ;# first entry in first consumer's PEL
        assert_equal [lindex $reply 11 1 1] "g2" ;# second group name
        assert_equal [lindex $reply 11 1 9 0 1] "Charlie" ;# first consumer
        assert_equal [lindex $reply 11 1 9 0 7 0 0] "100-0" ;# first entry in first consumer's PEL
        assert_equal [lindex $reply 11 1 9 0 7 1 0] "101-0" ;# second entry in first consumer's PEL

        set reply [r XINFO STREAM x FULL COUNT 1]
        assert_equal [llength $reply] 12
        assert_equal [lindex $reply 1] 4
        assert_equal [lindex $reply 9] "{100-0 {a 1}}"
    }

    test {XGROUP CREATECONSUMER: create consumer if does not exist} {
        r del mystream
        r XGROUP CREATE mystream mygroup $ MKSTREAM
        r XADD mystream * f v

        set reply [r xinfo groups mystream]
        set group_info [lindex $reply 0]
        set n_consumers [lindex $group_info 3]
        assert_equal $n_consumers 0 ;# consumers number in cg

        # create consumer using XREADGROUP
        r XREADGROUP GROUP mygroup Alice COUNT 1 STREAMS mystream >

        set reply [r xinfo groups mystream]
        set group_info [lindex $reply 0]
        set n_consumers [lindex $group_info 3]
        assert_equal $n_consumers 1 ;# consumers number in cg

        set reply [r xinfo consumers mystream mygroup]
        set consumer_info [lindex $reply 0]
        assert_equal [lindex $consumer_info 1] "Alice" ;# consumer name

        # create group using XGROUP CREATECONSUMER when Alice already exists
        set created [r XGROUP CREATECONSUMER mystream mygroup Alice]
        assert_equal $created 0

        # create group using XGROUP CREATECONSUMER when Bob does not exist
        set created [r XGROUP CREATECONSUMER mystream mygroup Bob]
        assert_equal $created 1

        set reply [r xinfo groups mystream]
        set group_info [lindex $reply 0]
        set n_consumers [lindex $group_info 3]
        assert_equal $n_consumers 2 ;# consumers number in cg

        set reply [r xinfo consumers mystream mygroup]
        set consumer_info [lindex $reply 0]
        assert_equal [lindex $consumer_info 1] "Alice" ;# consumer name
        set consumer_info [lindex $reply 1]
        assert_equal [lindex $consumer_info 1] "Bob" ;# consumer name
    }

    test {XGROUP CREATECONSUMER: group must exist} {
        r del mystream
        r XADD mystream * f v
        assert_error "*NOGROUP*" {r XGROUP CREATECONSUMER mystream mygroup consumer}
    }

    start_server {tags {"stream"} overrides {appendonly yes aof-use-rdb-preamble no appendfsync always}} {
        test {XREADGROUP with NOACK creates consumer} {
            r del mystream
            r XGROUP CREATE mystream mygroup $ MKSTREAM
            r XADD mystream * f1 v1
            r XREADGROUP GROUP mygroup Alice NOACK STREAMS mystream ">"
            set rd [redis_deferring_client]
            $rd XREADGROUP GROUP mygroup Bob BLOCK 0 NOACK STREAMS mystream ">"
            r XADD mystream * f2 v2
            set grpinfo [r xinfo groups mystream]

            r debug loadaof
            assert {[r xinfo groups mystream] == $grpinfo}
            set reply [r xinfo consumers mystream mygroup]
            set consumer_info [lindex $reply 0]
            assert_equal [lindex $consumer_info 1] "Alice" ;# consumer name
            set consumer_info [lindex $reply 1]
            assert_equal [lindex $consumer_info 1] "Bob" ;# consumer name
        }

        test {Consumer without PEL is present in AOF after AOFRW} {
            r del mystream
            r XGROUP CREATE mystream mygroup $ MKSTREAM
            r XADD mystream * f v
            r XREADGROUP GROUP mygroup Alice NOACK STREAMS mystream ">"
            set rd [redis_deferring_client]
            $rd XREADGROUP GROUP mygroup Bob BLOCK 0 NOACK STREAMS mystream ">"
            r XGROUP CREATECONSUMER mystream mygroup Charlie
            set grpinfo [lindex [r xinfo groups mystream] 0]

            r bgrewriteaof
            waitForBgrewriteaof r
            r debug loadaof

            set curr_grpinfo [lindex [r xinfo groups mystream] 0]
            assert {$curr_grpinfo == $grpinfo}
            set n_consumers [lindex $grpinfo 3]

            # Bob should be created only when there will be new data for this consumer
            assert_equal $n_consumers 2
            set reply [r xinfo consumers mystream mygroup]
            set consumer_info [lindex $reply 0]
            assert_equal [lindex $consumer_info 1] "Alice"
            set consumer_info [lindex $reply 1]
            assert_equal [lindex $consumer_info 1] "Charlie"
        }
    }

    start_server {} {
        set master [srv -1 client]
        set master_host [srv -1 host]
        set master_port [srv -1 port]
        set slave [srv 0 client]

        foreach noack {0 1} {
            test "Consumer group last ID propagation to slave (NOACK=$noack)" {
                $slave slaveof $master_host $master_port
                wait_for_condition 50 100 {
                    [s 0 master_link_status] eq {up}
                } else {
                    fail "Replication not started."
                }

                $master del stream
                $master xadd stream * a 1
                $master xadd stream * a 2
                $master xadd stream * a 3
                $master xgroup create stream mygroup 0

                # Consume the first two items on the master
                for {set j 0} {$j < 2} {incr j} {
                    if {$noack} {
                        set item [$master xreadgroup group mygroup \
                                  myconsumer COUNT 1 NOACK STREAMS stream >]
                    } else {
                        set item [$master xreadgroup group mygroup \
                                  myconsumer COUNT 1 STREAMS stream >]
                    }
                    set id [lindex $item 0 1 0 0]
                    if {$noack == 0} {
                        assert {[$master xack stream mygroup $id] eq "1"}
                    }
                }

                wait_for_ofs_sync $master $slave

                # Turn slave into master
                $slave slaveof no one

                set item [$slave xreadgroup group mygroup myconsumer \
                          COUNT 1 STREAMS stream >]

                # The consumed enty should be the third
                set myentry [lindex $item 0 1 0 1]
                assert {$myentry eq {a 3}}
            }
        }
    }

    start_server {tags {"stream"} overrides {appendonly yes aof-use-rdb-preamble no}} {
        test {Empty stream with no lastid can be rewrite into AOF correctly} {
            r XGROUP CREATE mystream group-name $ MKSTREAM
            assert {[dict get [r xinfo stream mystream] length] == 0}
            set grpinfo [r xinfo groups mystream]
            r bgrewriteaof
            waitForBgrewriteaof r
            r debug loadaof
            assert {[dict get [r xinfo stream mystream] length] == 0}
            assert {[r xinfo groups mystream] == $grpinfo}
        }
    }
}

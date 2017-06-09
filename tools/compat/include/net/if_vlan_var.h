/*-
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _NET_IF_VLAN_VAR_H_
#define	_NET_IF_VLAN_VAR_H_	1

/* Set the VLAN ID in an mbuf packet header non-destructively. */
#define EVL_APPLY_VLID(m, vlid)						\
	do {								\
		if ((m)->m_flags & M_VLANTAG) {				\
			(m)->m_pkthdr.ether_vtag &= EVL_VLID_MASK;	\
			(m)->m_pkthdr.ether_vtag |= (vlid);		\
		} else {						\
			(m)->m_pkthdr.ether_vtag = (vlid);		\
			(m)->m_flags |= M_VLANTAG;			\
		}							\
	} while (0)

/* Set the priority ID in an mbuf packet header non-destructively. */
#define EVL_APPLY_PRI(m, pri)						\
	do {								\
		if ((m)->m_flags & M_VLANTAG) {				\
			uint16_t __vlantag = (m)->m_pkthdr.ether_vtag;	\
			(m)->m_pkthdr.ether_vtag |= EVL_MAKETAG(	\
			    EVL_VLANOFTAG(__vlantag), (pri),		\
			    EVL_CFIOFTAG(__vlantag));			\
		} else {						\
			(m)->m_pkthdr.ether_vtag =			\
			    EVL_MAKETAG(0, (pri), 0);			\
			(m)->m_flags |= M_VLANTAG;			\
		}							\
	} while (0)

/* sysctl(3) tags, for compatibility purposes */
#define	VLANCTL_PROTO	1
#define	VLANCTL_MAX	2

/*
 * Configuration structure for SIOCSETVLAN and SIOCGETVLAN ioctls.
 */
struct	vlanreq {
	char	vlr_parent[IFNAMSIZ];
	u_short	vlr_tag;
};
#define	SIOCSETVLAN	SIOCSIFGENERIC
#define	SIOCGETVLAN	SIOCGIFGENERIC

#define	SIOCGVLANPCP	_IOWR('i', 152, struct ifreq)	/* Get VLAN PCP */
#define	SIOCSVLANPCP	 _IOW('i', 153, struct ifreq)	/* Set VLAN PCP */

/*
 * Names for 802.1q priorities ("802.1p").  Notice that in this scheme,
 * (0 < 1), allowing default 0-tagged traffic to take priority over background
 * tagged traffic.
 */
#define	IEEE8021Q_PCP_BK	1	/* Background (lowest) */
#define	IEEE8021Q_PCP_BE	0	/* Best effort (default) */
#define	IEEE8021Q_PCP_EE	2	/* Excellent effort */
#define	IEEE8021Q_PCP_CA	3	/* Critical applications */
#define	IEEE8021Q_PCP_VI	4	/* Video, < 100ms latency */
#define	IEEE8021Q_PCP_VO	5	/* Video, < 10ms latency */
#define	IEEE8021Q_PCP_IC	6	/* Internetwork control */
#define	IEEE8021Q_PCP_NC	7	/* Network control (highest) */


#endif /* _NET_IF_VLAN_VAR_H_ */

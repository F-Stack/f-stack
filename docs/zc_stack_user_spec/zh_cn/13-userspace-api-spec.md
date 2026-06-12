# 13 · 用户态 API 规格

> 全部包裹 `#ifdef FSTACK_ZC_RECV`。对称于 SEND 的 get/write/send，RECV 为 recv→read/segment→free 三段。

## 1. struct ff_zc_mbuf（复用，ff_api.h:347）
```c
struct ff_zc_mbuf {
    void *bsd_mbuf;       /* ZC-RECV: 内核交出的 mbuf 链首（m_freem 的对象）*/
    void *bsd_mbuf_off;   /* ZC-RECV: 遍历游标（当前读到的 mbuf）*/
    int   off;            /* ZC-RECV: 已读累计偏移，APP 不应改 */
    int   len;            /* ZC-RECV: 链总有效字节（=本次 recv 返回字节）*/
};
```
语义复用：SEND 时 off/len 是"已写/容量"，RECV 时是"已读/总有效"。

## 2. ff_zc_recv —— 零拷贝收取
```c
ssize_t ff_zc_recv(int fd, struct ff_zc_mbuf *zm, size_t nbytes);
```
| 项 | 规格 |
|---|---|
| 入参 | fd：socket；zm：出参容器（非 NULL）；nbytes：期望最大字节（映射 uio_resid）|
| 行为 | 经 kern_zc_recvit 透传 mp0，取回零拷贝 mbuf 链；填 zm->bsd_mbuf=链首、bsd_mbuf_off=链首、off=0、len=返回字节 |
| 返回 | >0：实际收取字节（=len）；0：对端关闭；-1：错误（errno）|
| 错误码 | EINVAL（zm==NULL/nbytes>INT_MAX）、EAGAIN（非阻塞无数据）、ECONNRESET 等沿用 soreceive |
| 误用防护 | 返回 >0 后 APP **必须**最终调用 ff_zc_recv_free（否则 mempool 泄漏）|

## 3. ff_zc_mbuf_read —— 读出/遍历（重写空 stub）
现状空 stub（ff_veth.c:359，签名 `const char *data` 与读出矛盾）。重设计：
```c
/* 方案1：拷贝读出到用户 buf（data 去 const 作 OUT）*/
int ff_zc_mbuf_read(struct ff_zc_mbuf *zm, char *out, int len);
/* 方案2（推荐，真零拷贝遍历）：返回当前段指针+长度，游标后移 */
int ff_zc_mbuf_segment(struct ff_zc_mbuf *zm, void **seg_data, int *seg_len);
```
| 项 | 规格（方案2）|
|---|---|
| 行为 | 从 bsd_mbuf_off 取当前 mbuf 的 mtod(m)/m_len，*seg_data/*seg_len 返回，游标 m_next 后移，off+=seg_len |
| 返回 | >0：本段字节；0：链已读完；-1：错误 |
| 零拷贝 | seg_data 直接指向 mbuf 数据（指向 DPDK mbuf），APP 在 free 前可安全访问 |

## 4. ff_zc_recv_free —— 归还整链
```c
void ff_zc_recv_free(struct ff_zc_mbuf *zm);
```
| 项 | 规格 |
|---|---|
| 行为 | `m_freem((struct mbuf*)zm->bsd_mbuf)`；逐段触发 ff_mbuf_ext_free→rte_pktmbuf_free_seg 归还 DPDK seg；清零 zm |
| 幂等 | bsd_mbuf==NULL 时 no-op |
| 约束 | 调用后 zm 不可再用于 read/segment（需重新 ff_zc_recv）|

## 5. 调用序列（对称 main_zc.c SEND）
```c
struct ff_zc_mbuf zm;
ssize_t n = ff_zc_recv(clientfd, &zm, sizeof_expect);
if (n > 0) {
    void *seg; int slen;
    while (ff_zc_mbuf_segment(&zm, &seg, &slen) > 0) {
        /* 零拷贝处理 seg[0..slen)（如转发/解析）*/
    }
    ff_zc_recv_free(&zm);   /* 必须！*/
}
```

## 6. 与现有 API 的关系
- 普通 ff_read/ff_recv/ff_recvfrom/ff_recvmsg **完全不变**（mp0 仍 NULL，拷贝路径）。
- ff_zc_recv 与普通 recv 互斥使用于同一次读取；混用不破坏正确性（各自独立 soreceive 调用）。

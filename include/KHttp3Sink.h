#ifndef KGL_HTTP3_INCLUDED_H_
#define KGL_HTTP3_INCLUDED_H_
#include "KSink.h"
#include "KHttp3.h"
#ifdef ENABLE_HTTP3
#include "lsxpack_header.h"
#include "kfiber_sync.h"
#include "KHttp3Connection.h"
#include "kfiber.h"
#include <vector>
// LSQUIC has no public stream-reset API accepting an HTTP/3 error code.
// Keep this compatibility boundary here; supported builds use LSQUIC 4.10+.
extern "C" void lsquic_stream_maybe_reset(struct lsquic_stream*, uint64_t, int);
struct header_decoder;
struct kgl_fiber_event {
    kfiber_cond* cd;
    WSABUF* buf;
    int bc;
    int result;
    bool waiting;
    int64_t active;
};
class KHttp3Sink final : public KSink {
public:
    KHttp3Sink(KHttp3Connection* cn, lsquic_stream_t* stream);
    ~KHttp3Sink();
    bool is_processing() const { return processing; }
    void detach_stream();
    void on_reset(int how);
    void on_headers(lsquic_stream_t* stream);
    void on_read(lsquic_stream_t* stream);
    void on_write(lsquic_stream_t* stream);
    void start(int got) override;
    bool set_transfer_chunked() override { return false; }
    using KSink::response_header;
    bool response_header(const char* name, int nlen, const char* value, int vlen) override;
    bool response_headers(const KHttpHeader* headers) override { return khttpd::response_headers<KHttp3Sink>(this, headers); }
    bool response_early_hints(const KHttpHeader* headers) override;
    bool response_trailer(const char* name, int nlen, const char* value, int vlen) override;
    KHttpHeader* get_trailer() override { return request_trailers.header; }
    bool finish_read_body() override;
    bool need_request_end() override { return !input_eof || request_trailers.header != nullptr; }
    bool readhup(void* arg, result_callback result) override;
    void remove_readhup() override { hup_result = nullptr; hup_arg = nullptr; }
    bool is_locked() override { return ev[0].waiting || ev[1].waiting; }
    int write_all(const kbuf* buf, int length) override;
    int write_all(const char* str, int length) override;
    void shutdown() override;
    void cancel_read() override;
    void set_time_out(int count) override;
    int get_time_out() override { return timeout_count; }
    void end_request() override;
    void flush() override { if (st) lsquic_stream_flush(st); }
    int64_t get_response_left() override { return content_left; }
    kgl_pool_t* get_connection_pool() override { return cn->get_pool(); }
    void* get_sni() override { return cn->get_sni(); }
    bool get_self_addr(sockaddr_i* addr) override {
        if (!cn->c || !cn->local_addr) return false;
        memcpy(addr, cn->local_addr, ksocket_addr_len((sockaddr_i*)cn->local_addr));
        return true;
    }
    sockaddr_i* get_peer_addr() override { return cn->c ? (sockaddr_i*)cn->peer_addr : nullptr; }
    kselector* get_selector() override { return cn->engine->uc->st.base.selector; }
    uint32_t get_server_model() override { return cn->engine->server->flags; }
    KOPAQUE get_server_opaque() override { return cn->engine->server->get_data(); }
    int check_timeout();
protected:
    int internal_read(char* buf, int len) override;
    bool internal_response_status(uint16_t status) override;
    int internal_start_response_body(int64_t size, bool interim) override;
private:
    bool add_header(std::vector<lsxpack_header>& headers, const char* name, int nlen, const char* value, int vlen);
    bool send_headers(std::vector<lsxpack_header>& headers);
    int internal_write(WSABUF* buf, int count);
    int wait(int op);
    void complete(int op, int result);
    void abort_stream(uint64_t error, int result = -1);
    void notify_hup(int result);
    lsquic_stream_t* st;
    KHttp3Connection* cn;
    std::vector<lsxpack_header> response_fields, response_trailers;
    std::vector<lsxpack_header>* pending_headers = nullptr;
    KHttpHeaderManager request_trailers{};
    kgl_fiber_event ev[2]{};
    kselector_tick* timeout_tick = nullptr;
    result_callback hup_result = nullptr;
    void* hup_arg = nullptr;
    int64_t hup_active = 0;
    int64_t content_left = 0, request_length = -1, body_read = 0;
    int timeout_count = 0;
    bool processing = false, header_received = false, trailer_received = false;
    bool final_sent = false, ended = false, aborted = false, input_eof = false, read_canceled = false;
};
struct header_decoder {
    lsxpack_header xhdr;
    char decode_buf[64 * 1024];
    KHttpHeaderManager fields{};
    size_t bytes;
    unsigned count;
    bool invalid;
    header_decoder() : bytes(0), count(0), invalid(false) { memset(&xhdr, 0, sizeof(xhdr)); }
    ~header_decoder() { free_header_list(fields.header); }
};
inline void free_header_decoder(header_decoder* hset) { delete hset; }
#endif
#endif

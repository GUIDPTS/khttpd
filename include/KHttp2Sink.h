#ifndef KHTTP2SINK_H_99
#define KHTTP2SINK_H_99 1
#include "KTcpServerSink.h"
#include "KHttp2.h"
#include "KHttpServer.h"
#ifdef ENABLE_HTTP2
class KHttp2Sink final : public KTcpServerSink
{
public:
	KHttp2Sink(KHttp2* http2, KHttp2Context* ctx, kgl_pool_t* pool) : KTcpServerSink(pool) {
		this->http2 = http2;
		this->ctx = ctx;
	}
	~KHttp2Sink() {
		if (ctx == NULL) {
			//the stream never started, KHttp2::ReleaseStateStream release it.
			return;
		}
		KBIT_SET(data.flags, RQ_CONNECTION_CLOSE);
		if (unlikely(ctx->content_left > 0)) {
			http2->shutdown(ctx);
		} else {
			if (KBIT_TEST(data.flags, RQ_HAVE_EXPECT)) {
				ctx->in_closed = 1;
			}
			http2->write_end(ctx);
		}
		http2->release(ctx);
	}
	virtual bool set_transfer_chunked() override {
		return false;
	}
	int64_t get_response_left() override {
		return ctx->content_left;
	}
	bool support_sendfile() override {
		return selectable_support_sendfile(&http2->c->st);
	}
	virtual int sendfile(kfiber_file* fp, int len) override {
		return http2->sendfile(ctx, fp, len);
	}
	KHttpHeader* get_trailer() override {
		if (!ctx->trailer) {
			return nullptr;
		}
		return ctx->trailer->get_header();
	}
	virtual bool internal_response_status(uint16_t status_code) override {
		if (status_code==101 && KBIT_TEST(data.flags,RQ_HAS_CONNECTION_UPGRADE)) status_code=200;
		return http2->add_status(ctx, status_code);
	}
	virtual bool response_header(kgl_header_type know_header, const char* val, int val_len, bool lock_value) override {
		if (know_header==kgl_header_connection || know_header==kgl_header_keep_alive ||
			know_header==kgl_header_transfer_encoding || know_header==kgl_header_upgrade) return true;
		return http2->add_header(ctx, know_header, val, (hlen_t)val_len);
	}
	virtual bool response_header(const char* name, int name_len, const char* val, int val_len) override {
		if (khttp_field_equal(name,name_len,"connection") || khttp_field_equal(name,name_len,"keep-alive") ||
			khttp_field_equal(name,name_len,"proxy-connection") || khttp_field_equal(name,name_len,"transfer-encoding") ||
			khttp_field_equal(name,name_len,"upgrade") || khttp_field_equal(name,name_len,"te")) return true;
		return http2->add_header(ctx, name, name_len, val, val_len);
	}
	virtual bool response_headers(const KHttpHeader* header) override {
		return khttpd::response_headers<KHttp2Sink>(this, header);
	}
	bool response_early_hints(const KHttpHeader* headers) override {
		if (data.status_code || ctx->out_closed || KBIT_TEST(data.flags, RQ_HAS_SEND_HEADER)) return false;
		auto pending = ctx->send_header;
		ctx->send_header = nullptr;
		bool success = http2->add_status(ctx, 103) && response_headers(headers);
		if (success) success = http2->send_header(ctx, false, true) > 0;
		delete ctx->send_header;
		ctx->send_header = pending;
		return success;
	}
	//返回头长度,-1表示出错
	int internal_start_response_body(int64_t body_size, bool is_100_continue) override {
		if (is_100_continue) {
			return http2->send_header(ctx, false);
		}
		send_alt_svc_header();
		ctx->set_content_length(body_size);
		ctx->defer_end = 1;
		return http2->send_header(ctx, false);
	}
	bool finish_read_body() override {
		char extra;
		return data.left_read == 0 && http2->read(ctx, &extra, 1) == 0;
	}
	bool need_request_end() override { return !ctx->in_closed || get_trailer() != nullptr; }
	bool is_locked() override {
		if (ctx->read_wait) {
			return true;
		}
		if (ctx->write_wait && !IS_WRITE_WAIT_FOR_HUP(ctx->write_wait)) {
			return true;
		}
		return false;
	}
	bool readhup(void* arg, result_callback result) override {
		return http2->readhup(ctx, result, arg);
	}
	void remove_readhup() override {
		http2->remove_readhup(ctx);
	}
	int internal_read(char* buf, int len) override {
		return http2->read(ctx, buf, len);
	}
	int write_all(const kbuf* buf, int length) override {
		int left = http2->write_all(ctx, buf, length);
		add_down_flow(nullptr, length - left);
		return left;
	}
	int write_all(const char* str, int length) override {
		kbuf buf{ 0 };
		buf.data = (char*)str;
		buf.used = length;
		return write_all(&buf, length);
	}
	void shutdown() override {
		return http2->shutdown(ctx);
	}
	void cancel_read() override { http2->cancel_read(ctx); }
	kconnection* get_connection() override {
		return http2->c;
	}
	void set_time_out(int tmo_count) override {
		ctx->tmo = tmo_count;
		ctx->tmo_left = tmo_count;
	}
	int get_time_out() override {
		return ctx->tmo;
	}
	void flush() override {}
	void start(int got) override {
		khttp_server_new_request(this, got);
	}
	bool response_trailer(const char* name, int name_len, const char* val, int val_len) override {
		if (!khttp_valid_trailer(name, name_len, val, val_len) || ctx->out_closed || ctx->content_left > 0) return false;
		if (!ctx->write_trailer) {
			if (ctx->send_header) {
				http2->send_header(ctx, false);
			}
			ctx->write_trailer = 1;
		}
		return http2->add_header(ctx, name, name_len, val, val_len);
	}

	bool parse_header(const char* attr, int attr_len, const char* val, int val_len);
protected:
	friend class KHttp2;

	bool response_altsvc_header(const char* val, int val_len) override {
		return response_header(_KS("Alt-Svc"), val, val_len);
		//return http2->send_altsvc(ctx, val, val_len);
	}
private:
	KHttp2Context* ctx;
	KHttp2* http2;
};
#endif
#endif

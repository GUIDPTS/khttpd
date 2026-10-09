#include "KHttp2Upstream.h"
#include "KStringBuf.h"
#include "khttp.h"
#include "KHttpKeyValue.h"

#ifdef ENABLE_UPSTREAM_HTTP2
bool KHttp2Upstream::parse_header(const char* attr, int attr_len, const char* val, int val_len, bool end_stream) {
	if (ctx->parsed_header) {
		return ctx->get_trailer_header()->add_header(attr, attr_len, val, val_len) != nullptr;
	}
	terminal_headers = end_stream;
	if (kgl_mem_same(attr, attr_len, _KS(":status"))) {
		pending_status = (int)kgl_atol((u_char *)val, val_len);
		if (ctx->has_upgrade && pending_status == 200) pending_status = 101;
		if (pending_status >= 100 && pending_status < 200 && pending_status != 101) {
			//next headers is not trailer header
			ctx->is_100_continue = 1;
			assert(ctx->parsed_header == 0);
		}
		return true;
	}
	// Delivery happens in read_header's fiber. Writing an interim response can
	// yield, while this connection's parser receives more complete HEADERS blocks.
	return initial_headers.add_header(attr, attr_len, val, val_len) != nullptr;
}
bool KHttp2Upstream::finish_headers() {
	if (ctx->parsed_header) return true;
	if (!pending_status || response_heads.size() >= 9) return false;
	bool grpc = terminal_headers && initial_headers.find(_KS("grpc-status")) != nullptr;
	KHttpHeaderManager fields{};
	auto h = initial_headers.steal_header();
	while (h) {
		auto next = h->next;
		h->next = nullptr;
		if (grpc && khttp_valid_trailer(h->buf, h->name_len, h->buf + h->val_offset, h->val_len)) {
			ctx->get_trailer_header()->insert(h);
		} else fields.insert(h);
		h = next;
	}
	response_heads.push_back({pending_status, fields.steal_header()});
	pending_status = 0;
	terminal_headers = false;
	return true;
}
bool KHttp2Upstream::set_header_callback(void* arg, kgl_header_callback header) {
	assert(kselector_is_same_thread(http2->c->st.base.selector));
	assert(!ctx->in_closed);
	assert(ctx->read_wait == NULL);
	kgl_http2_event* e = new kgl_http2_event;
	e->header_arg = arg;
	e->header = header;
	ctx->read_wait = e;
	header_callback = header;
	header_arg = arg;
	return true;
}
KGL_RESULT KHttp2Upstream::read_header() {
	read_header_time = kgl_current_sec;
	if (ctx->send_header) {
		http2->send_header(ctx, ctx->content_left == 0 && !ctx->defer_end);
	}
	if (response_heads.empty() && http2->ReadHeader(ctx) != 0) return KGL_EUNKNOW;
	if (response_heads.empty()) return KGL_EUNKNOW;
	auto head = response_heads.front();
	response_heads.pop_front();
	bool success = header_callback(this, header_arg, nullptr, (int)kgl_header_status,
		(const char*)&head.status, KGL_HEADER_VALUE_INT, false);
	for (auto h = head.headers; success && h; h = h->next) {
		success = header_callback(this, header_arg, h->buf, h->name_len, h->buf + h->val_offset, h->val_len, false);
	}
	free_header_list(head.headers);
	return success ? KGL_OK : KGL_EDATA_FORMAT;
}
KUpstream* KHttp2Upstream::NewStream() {
	kassert(this->ctx->admin_stream);
	return http2->connect();
}
bool KHttp2Upstream::send_trailer(const char* name, hlen_t name_len, const char* val, hlen_t val_len) {
	if (!khttp_valid_trailer(name, name_len, val, val_len) || ctx->out_closed || ctx->content_left > 0) return false;
	if (!ctx->write_trailer) {
		if (ctx->send_header) {
			http2->send_header(ctx, false);
		}
		ctx->write_trailer = 1;
	}
	return http2->add_header(ctx, name, name_len, val, val_len);
}
bool KHttp2Upstream::send_header(kgl_header_type name, const char* val, hlen_t val_len) {
	switch (name) {
	case kgl_header_expect:
		ctx->has_expect = 1;
		return KUpstream::send_header(name, val, val_len);
	case kgl_header_upgrade:
		if (ctx->has_upgrade) {
			upgrade_protocol.assign(val, val_len);
			return http2->add_header(ctx, _KS(":protocol"), val, val_len);
		}
		return KUpstream::send_header(name, val, val_len);
	default:
		return KUpstream::send_header(name, val, val_len);
	}
}
bool KHttp2Upstream::send_header(const char* attr, hlen_t attr_len, const char* val, hlen_t val_len) {
	return http2->add_header(ctx, attr, attr_len, val, val_len);
}
bool KHttp2Upstream::send_method_path(uint16_t meth, const char* path, hlen_t path_len) {
	ctx->head_request = meth == METH_HEAD;
	if (!http2->add_method(ctx, (uint8_t)meth)) {
		return false;
	}
	if (meth == METH_CONNECT) {
		ctx->has_upgrade = 1;
		ctx->set_content_length(-1);
	}
	return http2->add_header(ctx, kgl_expand_string(":path"), path, path_len);
}
bool KHttp2Upstream::send_host(const char* host, hlen_t host_len) {
	return http2->add_header(ctx, kgl_expand_string(":authority"), host, host_len);
}
void KHttp2Upstream::set_content_length(int64_t content_length) {
	if (ctx->has_upgrade) {
		return;
	}
	ctx->set_content_length(content_length);
	ctx->defer_end = content_length != 0 || ctx->duplex;
}
KGL_RESULT KHttp2Upstream::send_header_complete() {
	return KGL_OK;
}
#endif

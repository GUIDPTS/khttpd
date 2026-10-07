#ifndef KHTTP_VALIDATION_H
#define KHTTP_VALIDATION_H
#include "KHttpParser.h"
#include "kstring.h"

// Keep the existing generous byte limits; also bound allocations for tiny fields.
#define KHTTP_MAX_FIELD_COUNT 1024
inline bool khttp_field_equal(const char* name, int len, const char* text) {
	return len == (int)strlen(text) && strncasecmp(name, text, len) == 0;
}
inline bool khttp_valid_field(const char* name, int nlen, const char* value, int vlen, bool multiplex = false) {
	if (!name || !value || nlen <= 0 || vlen < 0) return false;
	int start = multiplex && name[0] == ':' ? 1 : 0;
	if (start == nlen) return false;
	for (int i = start; i < nlen; ++i) {
		unsigned char c = (unsigned char)name[i];
		if (!khttp_is_token(c) || (multiplex && c >= 'A' && c <= 'Z')) return false;
	}
	for (int i = 0; i < vlen; ++i) {
		unsigned char c = (unsigned char)value[i];
		if ((c < 32 && c != '\t') || c == 127) return false;
	}
	return !multiplex || vlen == 0 ||
		((value[0] != ' ' && value[0] != '\t') && (value[vlen-1] != ' ' && value[vlen-1] != '\t'));
}
inline bool khttp_valid_trailer(const char* name, int nlen, const char* value, int vlen, bool multiplex = false) {
	if (!khttp_valid_field(name, nlen, value, vlen, multiplex) || name[0] == ':') return false;
	static const char* forbidden[] = { "content-length", "transfer-encoding", "host", "connection",
		"keep-alive", "proxy-connection", "upgrade", "te", "trailer", "authorization",
		"proxy-authorization", "content-encoding", "content-type", "content-range" };
	for (auto field : forbidden) if (khttp_field_equal(name, nlen, field)) return false;
	return true;
}
inline bool khttp_parse_length(const char* value, int len, int64_t* result) {
	if (len <= 0) return false;
	int64_t n = 0;
	for (int i = 0; i < len; ++i) {
		if (value[i] < '0' || value[i] > '9' || n > (INT64_MAX - (value[i]-'0')) / 10) return false;
		n = n * 10 + value[i] - '0';
	}
	*result = n;
	return true;
}
struct KHttpHeaderValidation {
	unsigned count, pseudo;
	bool regular, connect;
	int status;
	void reset() { memset(this, 0, sizeof(*this)); }
	bool field(const char* name, int nlen, const char* value, int vlen, bool multiplex, bool request, bool trailer = false) {
		if (++count > KHTTP_MAX_FIELD_COUNT || !khttp_valid_field(name, nlen, value, vlen, multiplex)) return false;
		if (trailer) return khttp_valid_trailer(name, nlen, value, vlen, multiplex);
		if (!multiplex) return true;
		if (name[0] == ':') {
			if (regular) return false;
			unsigned bit = 0;
			if (request) {
				if (khttp_field_equal(name,nlen,":method")) { bit=1; connect=vlen==7 && memcmp(value,"CONNECT",7)==0; }
				else if (khttp_field_equal(name,nlen,":scheme")) { bit=2; if (!khttp_field_equal(value,vlen,"http") && !khttp_field_equal(value,vlen,"https")) return false; }
				else if (khttp_field_equal(name,nlen,":path")) bit=4;
				else if (khttp_field_equal(name,nlen,":authority")) bit=8;
				else if (khttp_field_equal(name,nlen,":protocol")) bit=16;
			} else if (khttp_field_equal(name,nlen,":status")) {
				bit=32;
				if (vlen!=3 || value[0]<'1' || value[0]>'5' || value[1]<'0' || value[1]>'9' || value[2]<'0' || value[2]>'9') return false;
				status=(value[0]-'0')*100+(value[1]-'0')*10+value[2]-'0';
				if (status==101) return false;
			}
			if (!bit || (pseudo & bit) || vlen==0) return false;
			pseudo |= bit;
			return true;
		}
		regular = true;
		if (khttp_field_equal(name,nlen,"connection") || khttp_field_equal(name,nlen,"keep-alive") ||
			khttp_field_equal(name,nlen,"proxy-connection") || khttp_field_equal(name,nlen,"upgrade") ||
			khttp_field_equal(name,nlen,"transfer-encoding")) return false;
		if (khttp_field_equal(name,nlen,"te") && (!request || !khttp_field_equal(value,vlen,"trailers"))) return false;
		return true;
	}
	bool complete(bool request, bool trailer = false) const {
		if (trailer) return pseudo == 0;
		if (!request) return pseudo == 32;
		if ((pseudo & 16) && !connect) return false;
		if (connect && !(pseudo & 16)) return pseudo == (1|8);
		return (pseudo & (1|2|4)) == (1|2|4);
	}
};
#endif

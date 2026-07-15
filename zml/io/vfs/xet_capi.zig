//! Zig binding over xet-core's C-API (`xet_capi`, ABI from `hf_xet.h`).
//!
//! Drives the mature Rust xet client (adaptive concurrency, streaming,
//! decompress-once, on-disk chunk cache) instead of
//! reimplementing the protocol in Zig. Reconstruction runs at the same
//! throughput as the official `hf-xet` client.
//!
//! The C symbols are declared `extern` here rather than pulled in via
//! `@cImport`, so the build only needs to link `libxet_capi` (no header include
//! path to thread through the build system).
//!
//! A `Session` reconstructs arbitrary byte ranges of a file (`readRange`), used
//! for positional VFS reads. Overlapping ranges hit the on-disk chunk cache.
//! `HF_XET_HIGH_PERFORMANCE=1` enables peak concurrency/buffers, like `hf-xet`.
//! Auth (CAS endpoint + read token) comes from `xet_hub.requestReadToken`.

const std = @import("std");

const log = std.log.scoped(.@"zml/io/vfs/xet_capi");

// -- opaque handles --
const XetSession = opaque {};
const XetDownloadStreamGroup = opaque {};
const XetDownloadStream = opaque {};
const XetFileInfo = opaque {};
const XetError = opaque {};
const XetBytes = opaque {};

const XetHeader = extern struct {
    key: ?[*:0]const u8,
    value: ?[*:0]const u8,
};

const XetAuthConfig = extern struct {
    endpoint: ?[*:0]const u8,
    token: ?[*:0]const u8,
    token_expiry: i64,
    token_refresh_url: ?[*:0]const u8,
    refresh_headers: ?[*]const XetHeader,
    refresh_header_count: usize,
};

// XetStatus: 0 = Ok.
const XET_OK: c_int = 0;

extern fn xet_session_new(out: *?*XetSession, err: *?*XetError) c_int;
extern fn xet_session_free(session: ?*XetSession) void;
extern fn xet_session_new_download_stream_group(session: ?*XetSession, cfg: *const XetAuthConfig, out: *?*XetDownloadStreamGroup, err: *?*XetError) c_int;
extern fn xet_download_stream_group_free(group: ?*XetDownloadStreamGroup) void;
extern fn xet_file_info_new(hash: [*:0]const u8, file_size: u64, out: *?*XetFileInfo, err: *?*XetError) c_int;
extern fn xet_file_info_free(fi: ?*XetFileInfo) void;
extern fn xet_download_stream_group_download_stream(group: ?*XetDownloadStreamGroup, file_info: ?*XetFileInfo, has_range: bool, range_start: u64, range_end: u64, out: *?*XetDownloadStream, err: *?*XetError) c_int;
// Blocking: fetches the next chunk, `*out` is NULL at end of stream. `offset`
// is only written for unordered streams, so we pass null for ordered reads.
extern fn xet_download_stream_next(stream: ?*XetDownloadStream, offset: ?*u64, out: *?*XetBytes, err: *?*XetError) c_int;
extern fn xet_download_stream_free(stream: ?*XetDownloadStream) void;
extern fn xet_bytes_data(b: ?*XetBytes) [*]const u8;
extern fn xet_bytes_len(b: ?*XetBytes) usize;
extern fn xet_bytes_free(b: ?*XetBytes) void;
extern fn xet_error_message(err: ?*XetError) [*:0]const u8;
extern fn xet_error_code(err: ?*XetError) c_int;
extern fn xet_error_free(err: ?*XetError) void;

fn capiError(err: ?*XetError) error{XetCapi} {
    if (err) |e| {
        log.err("xet_capi: {s} (code {d})", .{ xet_error_message(e), xet_error_code(e) });
        xet_error_free(e);
    }
    return error.XetCapi;
}

/// A live xet-core download session bound to one CAS endpoint + token.
pub const Session = struct {
    session: *XetSession,
    stream_group: *XetDownloadStreamGroup,

    pub fn init(cas_url: [:0]const u8, token: [:0]const u8, token_expiry: i64) !Session {
        var err: ?*XetError = null;

        var session: ?*XetSession = null;
        if (xet_session_new(&session, &err) != XET_OK) return capiError(err);
        errdefer xet_session_free(session);

        const cfg = XetAuthConfig{
            .endpoint = cas_url.ptr,
            .token = token.ptr,
            .token_expiry = token_expiry,
            .token_refresh_url = null,
            .refresh_headers = null,
            .refresh_header_count = 0,
        };

        var stream_group: ?*XetDownloadStreamGroup = null;
        if (xet_session_new_download_stream_group(session, &cfg, &stream_group, &err) != XET_OK) return capiError(err);

        return .{ .session = session.?, .stream_group = stream_group.? };
    }

    pub fn deinit(self: *Session) void {
        xet_download_stream_group_free(self.stream_group);
        xet_session_free(self.session);
    }

    /// Reconstruct `[start, end)` of the file (hex XET hash + size) into `dest`,
    /// returning bytes written. Only the covering xorbs are fetched; overlapping
    /// ranges are served from the chunk cache.
    pub fn readRange(self: *Session, hash_hexz: [:0]const u8, size: u64, start: u64, end: u64, dest: []u8) !usize {
        var err: ?*XetError = null;

        var fi: ?*XetFileInfo = null;
        if (xet_file_info_new(hash_hexz.ptr, size, &fi, &err) != XET_OK) return capiError(err);
        defer xet_file_info_free(fi);

        var stream: ?*XetDownloadStream = null;
        if (xet_download_stream_group_download_stream(self.stream_group, fi, true, start, end, &stream, &err) != XET_OK) return capiError(err);
        defer xet_download_stream_free(stream);

        var written: usize = 0;
        while (written < dest.len) {
            // Blocking call; ordered stream, so `offset` is left null.
            var bytes: ?*XetBytes = null;
            if (xet_download_stream_next(stream, null, &bytes, &err) != XET_OK) return capiError(err);
            const b = bytes orelse break; // null = EOF

            const src = xet_bytes_data(b)[0..xet_bytes_len(b)];
            const n = @min(src.len, dest.len - written);
            @memcpy(dest[written..][0..n], src[0..n]);
            written += n;
            xet_bytes_free(b);
        }
        return written;
    }
};

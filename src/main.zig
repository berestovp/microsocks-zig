const std = @import("std");
const clap = @import("clap");
const network = @import("network");
const posix = std.posix;
const net = std.net;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const connError = net.TcpConnectToAddressError;

pub const failure_timeoute = 64 * 1000;
pub const thread_stack_size =  72 * 1024;
    
pub var authenticator: ?Authenticator = null; 
pub var authed_ips: ?AuthedAddressList = null;
pub var auth_once: bool = false;
 
const ErrorCode = enum {
	Success,
	GeneralFailure,
	NotAllowed,
	NetUnreachable,
	HostUunreachable,
	ConnRefused,
	TTLExpird, 
	CommandNodSupported,
	AddressTypeNotSupported,
};

const AuthMethod = enum(u8) {
    None = 0,
    GSSApi = 1,
    Username = 2, 
    NoAcceptable = 255,
};

const ClientState = enum {
    CS1_Connected,
    CS2_NeedAuth,
    CS3_Authed,
}; 

const ClientThread = struct {
        th: Thread,
        client: Client,
        state: ClientState, 
        done: bool,
};

const Client = struct {
    addr: network.Address,
    sock: network.Socket,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    try network.init();
    defer network.deinit();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help Display this help and exit.
        \\-u, --user <str> Specify the username for authentication.
        \\-P, --pass <str> Specify the password for authentication. 
        \\-w, --white_list <str>... Allow access without authentication for specified IP addresses. 
        \\-1, --auth_once  Authenticate once from the current IP address, bypassing further authentications.
        \\
    );

    const errWriter = std.io.getStdErr().writer();

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.report(errWriter, err) catch {};
        return clap.help(errWriter, clap.Help, &params, .{});
    };
    defer res.deinit();

    if (res.args.help != 0)
        return clap.help(errWriter, clap.Help, &params, .{});

    if (res.args.user != null or res.args.pass != null) {
        const name = res.args.user orelse {
            return clap.help(errWriter, clap.Help, &params, .{});
        };

        const pass = res.args.pass orelse {
            return clap.help(errWriter, clap.Help, &params, .{});
        };

        var upa = UsernameAuth{.name = name, .pass = pass};
        authenticator = UsernameAuth.authenticator(&upa);
    }

    authed_ips = AuthedAddressList.init(allocator);
    defer authed_ips.?.deinit();
    for (res.args.white_list) |s| {
        const addr = try network.Address.parse(s);
        try authed_ips.?.add(addr);
    }

    auth_once = (res.args.auth_once != 0);

    var server = try Server.init(allocator, "0.0.0.0:3667");
    defer server.deinit();
    std.log.info("server start at 0.0.0.0:3667", .{});
    try server.run();
}

pub const Authenticator = struct {
    ptr: *anyopaque,
    impl: *const Interface,

    pub const Interface = struct {
        checkCredential: *const fn (ctx: *anyopaque, user: []const u8, pass: []const u8) ErrorCode,
    };

    pub fn checkCredential(self: Authenticator, user: []const u8, pass: []const u8) ErrorCode {
        return self.impl.checkCredential(self.ptr, user, pass);
    }
};

pub const UsernameAuth = struct {
    name: []const u8,
    pass: []const u8,

    pub fn checkCredential(ctx: *anyopaque, user: []const u8, pass: []const u8) ErrorCode {
        const self: *UsernameAuth = @ptrCast(@alignCast(ctx));
        var status = ErrorCode.GeneralFailure;
        if (std.mem.eql(u8, self.name, user) and  std.mem.eql(u8, self.pass, pass))  
            status =  ErrorCode.Success;
            return status;
    }

    pub fn authenticator(self: *UsernameAuth) Authenticator {
        return Authenticator{
            .ptr = self,
            .impl = &.{.checkCredential = checkCredential},
        };
    }
};

pub const AuthedAddressList = struct {
    mutex: Mutex,
    list: std.ArrayList(network.Address),
    
    pub fn init(allocator: std.mem.Allocator) AuthedAddressList {
        return AuthedAddressList {
            .mutex = .{}, 
            .list = std.ArrayList(network.Address).init(allocator),
        };
    }

    pub fn deinit(self: *AuthedAddressList) void {
        self.deinit();
    }

    pub fn add(self: *AuthedAddressList, addr: network.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.list.append(addr);
    }

    pub fn contains(self: *AuthedAddressList, addr: network.Address) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.list.items) |cur_addr| 
            if (addr.eql(cur_addr)) return true;
        return false;
    }
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    listener: network.Socket,

    pub fn init(
        allocator: std.mem.Allocator, 
        listen_addr: []const u8, 
    ) !Server { 
        const addr = try network.EndPoint.parse(listen_addr);
        var listener = try network.Socket.create(.ipv4, .tcp);
        try listener.enablePortReuse(true);
        try listener.bind(addr);
        try listener.listen();
        return Server {
            .allocator = allocator,
            .listener = listener,
        };
    }

    pub fn deinit(self: *const Server) void {
        self.listener.close();
    }

    pub fn run(self: *const Server) !void {
        var threads = std.ArrayList(*ClientThread).init(self.allocator);
        defer threads.deinit();

        while(true) {
            collect(&threads);
                                
            const cur = self.allocator.create(ClientThread) catch {
                std.time.sleep(failure_timeoute);
                continue;
            };

            const client = self.accept() catch {
                self.allocator.destroy(cur);
                std.time.sleep(failure_timeoute);
                continue;
            };

            cur.client = client;
            cur.done = false;
            threads.append(cur) catch {
                self.allocator.destroy(cur);
                client.sock.close();
                std.time.sleep(failure_timeoute);
                continue;            };

            cur.th = try Thread.spawn(.{.stack_size = thread_stack_size}, startTunel, .{
                self.allocator, 
                cur, 
            });
        }
    }

    fn accept(self: *const Server) !Client {
        const s = try self.listener.accept();
        const ep = try s.getRemoteEndPoint();
        return Client{.addr = ep.address, .sock = s};
    }

    fn startTunel(allocator: std.mem.Allocator, thread: *ClientThread) !void {
        const tunel = Tunel.init(allocator, thread);
        try tunel.create(); 
        tunel.shutdown();
        thread.done = true;
    }

    fn collect(threads: *std.ArrayList(*ClientThread)) void {
        var i: usize = 0;
        while(i < threads.items.len) : (i += 1) {
            if (threads.items[i].done) {
                const thread = threads.swapRemove(i);
                thread.th.join();
            }
        }
    }
};

pub const Tunel = struct {
    allocator: std.mem.Allocator, 
    thread: *ClientThread,

    pub fn init(allocator: std.mem.Allocator, thread: *ClientThread) Tunel {
        return Tunel{.allocator = allocator, .thread = thread, };
    }

    pub fn shutdown(self: *const Tunel) void {
        self.thread.client.sock.close();
    }  

    pub fn create(self: *const Tunel) !void {
        const target_sock = try self.handshake(); 
        errdefer target_sock.close();

        try self.copyLoop(self.thread.client.sock, target_sock); 
        target_sock.close();
    }

    fn copyLoop(self: *const Tunel, fd0: network.Socket, fd1: network.Socket) !void {
        var set = try network.SocketSet.init(self.allocator);
        defer set.deinit();
        try set.add(fd0, .{.read = true, .write = false});
        try set.add(fd1, .{.read = true, .write = false});
        while (true) {
            _ = try network.waitForSocketEvent(&set, null);
            const infd = if (set.isReadyRead(fd0)) fd0 else fd1;
            const outfd = if (infd.internal == fd1.internal) fd0 else fd1;
            const size = comptime blk: {break :blk @min(16*1024, thread_stack_size/2);}; 
            var buf: [size]u8 = undefined;
            const n = try infd.receive(&buf);
            if (n == 0) return;
            var sent: usize = 0;
            while (sent < n) {
                const data = buf[sent..n - sent];
                const m = try outfd.send(data);
                if (m == 0) return;
                    sent += m;
            }
        }
    }
    
    fn sendReply(self: *const Tunel, ec: ErrorCode) !void {
        const rep = &.{5, @intFromEnum(ec), 0, 1, 0, 0, 0, 0, 0, 0};
        _ = try self.thread.client.sock.send(rep);
    }

    fn parseIp4(addr: []const u8) !network.EndPoint {
        var sa: posix.sockaddr align(4) = std.mem.zeroInit(posix.sockaddr, .{});
        var sin: *posix.sockaddr.in = @ptrCast(@alignCast(&sa));
        sin.addr = std.mem.readInt(u32, addr[0..4], .little);
        sin.port = std.mem.readInt(u16, addr[4..6], .big);
        sin.port = std.mem.nativeToBig(u16, sin.port);
        sin.family = posix.AF.INET;
        return network.EndPoint.fromSocketAddress(&sa, @sizeOf(posix.sockaddr.in));
    }

    fn parseIp6(addr: []const u8) !network.EndPoint {
        var sa: posix.sockaddr align(4) = std.mem.zeroInit(posix.sockaddr, .{});
        var sin: *posix.sockaddr.in6 = @ptrCast(@alignCast(&sa));
        @memcpy(&sin.addr, addr[0..16]);
        sin.port = std.mem.readInt(u16, addr[16..18], .big);
        sin.port = std.mem.nativeToBig(u16, sin.port);
        sin.family = posix.AF.INET6;
        return network.EndPoint.fromSocketAddress(&sa, @sizeOf(posix.sockaddr.in6));
    }

    fn parseAddress(addr: []const u8) !network.EndPoint {
        return if (addr.len == 6) parseIp4(addr)
               else if (addr.len == 18) parseIp6(addr) else  unreachable;
    }

    fn connectToRemote(self: *const Tunel, buf: []const u8) !network.Socket {
        if (buf[0] != 5) return error.GeneralFailure;
        var addr: network.EndPoint = undefined;
        switch(buf[3]) {
            4, // Ipv6
            1 => // Ipv4 
               addr = try parseAddress(buf[4..buf.len]),
            3 => { // Domain
                const name = buf[5..buf.len-2];  
                const port_octets = std.mem.bytesAsValue([2]u8, buf[buf.len-2..buf.len]);
                const port = std.mem.readInt(u16, port_octets, .big);
                const res = try network.getEndpointList(self.allocator, name, port);
                defer network.EndpointList.deinit(res);
                addr =  res.endpoints[0];
            },

            else => {
                std.log.err("bad atype field", .{});
                return error.GeneralFailure;
            }
        }
        const af = @as(network.AddressFamily, addr.address);
        var remote_sock = try network.Socket.create(af, .tcp);
        try remote_sock.connect(addr);
        return remote_sock;
    }
    
    fn sendAuthStatus(self: *const Tunel, res: ErrorCode) !void {
        _ = try self.thread.client.sock.send(&.{1, @intFromEnum(res)});
    }

    fn sendAuthMethod(self: *const Tunel, method: AuthMethod) !void {
        _ = try self.thread.client.sock.send(&.{5, @intFromEnum(method)});
    }

    fn checkCredential( buf: []u8) !ErrorCode {
        if (buf.len < 5) return error.GeneralFailure;
        if (buf[0] != 1) return error.GeneralFailure;

        const ulen = buf[1];
        if (buf.len < 2 + ulen + 2) return error.GeneralFailure;

        const plen = buf[2+ulen];
        if(buf.len < 2 + ulen + 1 + plen) return error.GeneralFailure;

        const username = buf[2..2 + ulen];
        const pass = buf[2+ulen+1..2+ulen+1+plen];
        return authenticator.?.checkCredential(username, pass);
    }

    fn checkAuthMethod(self: *const Tunel, buf: []u8) !AuthMethod {
        if (buf[0] != 5) return error.GeneralFailure;

        var idx:usize = 1;
	    if(idx >= buf.len) return error.GeneralFailure;

	    var n_methods = buf[idx];
	    idx += 1;
	    while(idx < buf.len and n_methods > 0) : ({
	        idx+=1; n_methods -=1;
	    }){
		    if(buf[idx] == @intFromEnum(AuthMethod.None)) {
			    if(authenticator == null) return .None
			    else if(authed_ips != null and 
			        authed_ips.?.contains(self.thread.client.addr)) return .None;
		    } else if(buf[idx] == @intFromEnum(AuthMethod.Username)) {
			    if(authenticator != null) return .Username;
		    }
	    }
        return .NoAcceptable;
    }

    fn handshake(self: *const Tunel) !network.Socket{
        var buf: [1024]u8 = undefined;
        self.thread.state = ClientState.CS1_Connected;
        while(true) {
            const n = try self.thread.client.sock.receive(&buf);
            if (n == 0) break;
            switch(self.thread.state) {
                .CS1_Connected => {
                    const am = try self.checkAuthMethod(buf[0..n]);
                    if (am == .None)  self.thread.state = .CS3_Authed
                    else if (am == .Username) self.thread.state = .CS2_NeedAuth;
                    try self.sendAuthMethod(am);
                    if (am == .NoAcceptable) return error.GeneralFailure;
                },
                .CS2_NeedAuth => {
                    const res = try checkCredential(buf[0..n]);
                    try self.sendAuthStatus(res);
                    if (res != .Success) return error.UserRejected;
                    self.thread.state = .CS3_Authed;
                    if (auth_once and res == ErrorCode.Success) 
                        try authed_ips.?.add(self.thread.client.addr);
                },
                .CS3_Authed => {
                    const sock = self.connectToRemote(buf[0..n]) catch |err| {
                        var ec: ErrorCode = undefined;
                        switch(err) {
                            connError.NetworkUnreachable => ec = .NetUnreachable,
                            connError.ConnectionRefused => ec = .ConnRefused,
                            connError.ConnectionTimedOut => ec = .TTLExpird,
                            else => ec = .GeneralFailure,
                        }
                        try self.sendReply(ec);
                        return err;
                    };
                    try self.sendReply(.Success);
                    return sock;
                },
            }
        }
        return error.GeneralFailure; 
    }
};


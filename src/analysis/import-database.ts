/**
 * Enhanced Import Capability Database (v2.6)
 *
 * Comprehensive database of 500+ functions with:
 * - Capability classification
 * - Risk level assessment
 * - MITRE ATT&CK mapping
 * - Detailed descriptions
 */

import type { ImportCapability } from '../utils/import-analysis';

export interface ImportMetadata {
  name: string;
  capabilities: ImportCapability[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  category: string;
  mitreId?: string;
  aliases?: string[];
}

/**
 * Master import database - lookup by lowercase function name
 */
export const IMPORT_DATABASE: Map<string, ImportMetadata> = new Map();

// ============================================================================
// NETWORK FUNCTIONS (~80 functions)
// ============================================================================

const NETWORK_FUNCTIONS: ImportMetadata[] = [
  // Socket basics
  { name: 'socket', capabilities: ['Network'], riskLevel: 'medium', description: 'Create network socket', category: 'network' },
  { name: 'connect', capabilities: ['Network'], riskLevel: 'medium', description: 'Connect to remote host', category: 'network', mitreId: 'T1071' },
  { name: 'bind', capabilities: ['Network'], riskLevel: 'medium', description: 'Bind socket to local address', category: 'network' },
  { name: 'listen', capabilities: ['Network'], riskLevel: 'high', description: 'Listen for incoming connections', category: 'network', mitreId: 'T1571' },
  { name: 'accept', capabilities: ['Network'], riskLevel: 'high', description: 'Accept incoming connection', category: 'network' },
  { name: 'send', capabilities: ['Network'], riskLevel: 'medium', description: 'Send data on socket', category: 'network' },
  { name: 'sendto', capabilities: ['Network'], riskLevel: 'medium', description: 'Send UDP datagram', category: 'network' },
  { name: 'recv', capabilities: ['Network'], riskLevel: 'medium', description: 'Receive data from socket', category: 'network' },
  { name: 'recvfrom', capabilities: ['Network'], riskLevel: 'medium', description: 'Receive UDP datagram', category: 'network' },
  { name: 'select', capabilities: ['Network'], riskLevel: 'low', description: 'Monitor multiple sockets', category: 'network' },
  { name: 'poll', capabilities: ['Network'], riskLevel: 'low', description: 'Wait for socket events', category: 'network' },
  { name: 'shutdown', capabilities: ['Network'], riskLevel: 'low', description: 'Shutdown socket connection', category: 'network' },
  { name: 'closesocket', capabilities: ['Network'], riskLevel: 'low', description: 'Close socket', category: 'network' },
  { name: 'setsockopt', capabilities: ['Network'], riskLevel: 'low', description: 'Set socket options', category: 'network' },
  { name: 'getsockopt', capabilities: ['Network'], riskLevel: 'low', description: 'Get socket options', category: 'network' },
  { name: 'getsockname', capabilities: ['Network'], riskLevel: 'low', description: 'Get local socket address', category: 'network' },
  { name: 'getpeername', capabilities: ['Network'], riskLevel: 'low', description: 'Get remote socket address', category: 'network' },

  // Windows Sockets (Winsock)
  { name: 'wsastartup', capabilities: ['Network'], riskLevel: 'low', description: 'Initialize Winsock', category: 'network' },
  { name: 'wsacleanup', capabilities: ['Network'], riskLevel: 'low', description: 'Cleanup Winsock', category: 'network' },
  { name: 'wsasocket', capabilities: ['Network'], riskLevel: 'medium', description: 'Create Winsock socket', category: 'network', aliases: ['WSASocketA', 'WSASocketW'] },
  { name: 'wsaconnect', capabilities: ['Network'], riskLevel: 'medium', description: 'Connect with extended options', category: 'network' },
  { name: 'wsasend', capabilities: ['Network'], riskLevel: 'medium', description: 'Send with overlapped I/O', category: 'network' },
  { name: 'wsarecv', capabilities: ['Network'], riskLevel: 'medium', description: 'Receive with overlapped I/O', category: 'network' },
  { name: 'wsaasyncselect', capabilities: ['Network'], riskLevel: 'medium', description: 'Async socket events', category: 'network' },
  { name: 'wsaeventselect', capabilities: ['Network'], riskLevel: 'medium', description: 'Event-based socket I/O', category: 'network' },
  { name: 'wsagetlasterror', capabilities: ['Network'], riskLevel: 'low', description: 'Get Winsock error code', category: 'network' },
  { name: 'wsaioctl', capabilities: ['Network'], riskLevel: 'medium', description: 'Socket I/O control', category: 'network' },

  // DNS/Name resolution
  { name: 'getaddrinfo', capabilities: ['Network'], riskLevel: 'medium', description: 'Resolve hostname to address', category: 'network' },
  { name: 'gethostbyname', capabilities: ['Network'], riskLevel: 'medium', description: 'Resolve hostname (legacy)', category: 'network' },
  { name: 'gethostbyaddr', capabilities: ['Network'], riskLevel: 'low', description: 'Reverse DNS lookup', category: 'network' },
  { name: 'getnameinfo', capabilities: ['Network'], riskLevel: 'low', description: 'Address to hostname', category: 'network' },
  { name: 'freeaddrinfo', capabilities: ['Network'], riskLevel: 'low', description: 'Free address info', category: 'network' },
  { name: 'dnsquery', capabilities: ['Network'], riskLevel: 'medium', description: 'Direct DNS query', category: 'network', aliases: ['DnsQuery_A', 'DnsQuery_W'] },
  { name: 'gethostname', capabilities: ['Network', 'System'], riskLevel: 'low', description: 'Get local hostname', category: 'network' },

  // Address conversion
  { name: 'inet_addr', capabilities: ['Network'], riskLevel: 'low', description: 'Convert IP string to binary', category: 'network' },
  { name: 'inet_ntoa', capabilities: ['Network'], riskLevel: 'low', description: 'Convert binary IP to string', category: 'network' },
  { name: 'inet_pton', capabilities: ['Network'], riskLevel: 'low', description: 'Convert IP presentation to network', category: 'network' },
  { name: 'inet_ntop', capabilities: ['Network'], riskLevel: 'low', description: 'Convert IP network to presentation', category: 'network' },
  { name: 'htons', capabilities: ['Network'], riskLevel: 'low', description: 'Host to network short', category: 'network' },
  { name: 'htonl', capabilities: ['Network'], riskLevel: 'low', description: 'Host to network long', category: 'network' },
  { name: 'ntohs', capabilities: ['Network'], riskLevel: 'low', description: 'Network to host short', category: 'network' },
  { name: 'ntohl', capabilities: ['Network'], riskLevel: 'low', description: 'Network to host long', category: 'network' },

  // WinINet (High-level HTTP)
  { name: 'internetopen', capabilities: ['Network'], riskLevel: 'high', description: 'Initialize WinINet', category: 'network', mitreId: 'T1071.001', aliases: ['InternetOpenA', 'InternetOpenW'] },
  { name: 'internetconnect', capabilities: ['Network'], riskLevel: 'high', description: 'Connect to server', category: 'network', mitreId: 'T1071.001', aliases: ['InternetConnectA', 'InternetConnectW'] },
  { name: 'internetopenurl', capabilities: ['Network'], riskLevel: 'high', description: 'Open URL directly', category: 'network', mitreId: 'T1071.001', aliases: ['InternetOpenUrlA', 'InternetOpenUrlW'] },
  { name: 'httpopen', capabilities: ['Network'], riskLevel: 'high', description: 'Create HTTP request', category: 'network', aliases: ['HttpOpenRequestA', 'HttpOpenRequestW'] },
  { name: 'httpopenrequest', capabilities: ['Network'], riskLevel: 'high', description: 'Create HTTP request', category: 'network', aliases: ['HttpOpenRequestA', 'HttpOpenRequestW'] },
  { name: 'httpsendrequest', capabilities: ['Network'], riskLevel: 'high', description: 'Send HTTP request', category: 'network', mitreId: 'T1071.001', aliases: ['HttpSendRequestA', 'HttpSendRequestW'] },
  { name: 'httpqueryinfo', capabilities: ['Network'], riskLevel: 'medium', description: 'Query HTTP headers', category: 'network', aliases: ['HttpQueryInfoA', 'HttpQueryInfoW'] },
  { name: 'internetreadfile', capabilities: ['Network'], riskLevel: 'medium', description: 'Read HTTP response', category: 'network' },
  { name: 'internetwritefile', capabilities: ['Network'], riskLevel: 'high', description: 'Write HTTP data', category: 'network' },
  { name: 'internetclosehandle', capabilities: ['Network'], riskLevel: 'low', description: 'Close internet handle', category: 'network' },
  { name: 'internetsetstatuscallback', capabilities: ['Network'], riskLevel: 'low', description: 'Set progress callback', category: 'network' },
  { name: 'ftpopen', capabilities: ['Network'], riskLevel: 'high', description: 'Open FTP session', category: 'network', aliases: ['FtpOpenFileA', 'FtpOpenFileW'] },
  { name: 'ftpgetfile', capabilities: ['Network', 'FileIO'], riskLevel: 'high', description: 'Download file via FTP', category: 'network', aliases: ['FtpGetFileA', 'FtpGetFileW'] },
  { name: 'ftpputfile', capabilities: ['Network', 'FileIO'], riskLevel: 'high', description: 'Upload file via FTP', category: 'network', mitreId: 'T1048', aliases: ['FtpPutFileA', 'FtpPutFileW'] },

  // WinHTTP
  { name: 'winhttpopen', capabilities: ['Network'], riskLevel: 'high', description: 'Initialize WinHTTP', category: 'network', mitreId: 'T1071.001' },
  { name: 'winhttpconnect', capabilities: ['Network'], riskLevel: 'high', description: 'Connect to HTTP server', category: 'network', mitreId: 'T1071.001' },
  { name: 'winhttpopenrequest', capabilities: ['Network'], riskLevel: 'high', description: 'Create HTTP request', category: 'network' },
  { name: 'winhttpsendrequest', capabilities: ['Network'], riskLevel: 'high', description: 'Send HTTP request', category: 'network', mitreId: 'T1071.001' },
  { name: 'winhttpreceiveresponse', capabilities: ['Network'], riskLevel: 'medium', description: 'Receive HTTP response', category: 'network' },
  { name: 'winhttpreaddata', capabilities: ['Network'], riskLevel: 'medium', description: 'Read HTTP data', category: 'network' },
  { name: 'winhttpwritedata', capabilities: ['Network'], riskLevel: 'high', description: 'Write HTTP data', category: 'network' },
  { name: 'winhttpclosehandle', capabilities: ['Network'], riskLevel: 'low', description: 'Close WinHTTP handle', category: 'network' },
  { name: 'winhttpsetoption', capabilities: ['Network'], riskLevel: 'medium', description: 'Set WinHTTP option', category: 'network' },
  { name: 'winhttpcrackurl', capabilities: ['Network'], riskLevel: 'low', description: 'Parse URL components', category: 'network' },

  // URL handling
  { name: 'urldownloadtofile', capabilities: ['Network', 'FileIO'], riskLevel: 'critical', description: 'Download URL to file', category: 'network', mitreId: 'T1105', aliases: ['URLDownloadToFileA', 'URLDownloadToFileW'] },
  { name: 'urldownloadtocachefile', capabilities: ['Network', 'FileIO'], riskLevel: 'high', description: 'Download URL to cache', category: 'network', aliases: ['URLDownloadToCacheFileA', 'URLDownloadToCacheFileW'] },

  // Linux/POSIX network
  { name: 'socketpair', capabilities: ['Network'], riskLevel: 'low', description: 'Create socket pair', category: 'network' },
  { name: 'sendmsg', capabilities: ['Network'], riskLevel: 'medium', description: 'Send message on socket', category: 'network' },
  { name: 'recvmsg', capabilities: ['Network'], riskLevel: 'medium', description: 'Receive message from socket', category: 'network' },
  { name: 'epoll_create', capabilities: ['Network'], riskLevel: 'low', description: 'Create epoll instance', category: 'network' },
  { name: 'epoll_ctl', capabilities: ['Network'], riskLevel: 'low', description: 'Control epoll', category: 'network' },
  { name: 'epoll_wait', capabilities: ['Network'], riskLevel: 'low', description: 'Wait for epoll events', category: 'network' },
];

// ============================================================================
// PROCESS FUNCTIONS (~70 functions)
// ============================================================================

const PROCESS_FUNCTIONS: ImportMetadata[] = [
  // Process creation
  { name: 'createprocess', capabilities: ['Process'], riskLevel: 'high', description: 'Create new process', category: 'process', mitreId: 'T1106', aliases: ['CreateProcessA', 'CreateProcessW'] },
  { name: 'createprocessasuser', capabilities: ['Process'], riskLevel: 'critical', description: 'Create process as different user', category: 'process', mitreId: 'T1134', aliases: ['CreateProcessAsUserA', 'CreateProcessAsUserW'] },
  { name: 'createprocesswithlogon', capabilities: ['Process'], riskLevel: 'critical', description: 'Create process with credentials', category: 'process', mitreId: 'T1134', aliases: ['CreateProcessWithLogonW'] },
  { name: 'createprocesswithtoken', capabilities: ['Process'], riskLevel: 'critical', description: 'Create process with token', category: 'process', mitreId: 'T1134', aliases: ['CreateProcessWithTokenW'] },
  { name: 'shellexecute', capabilities: ['Process'], riskLevel: 'high', description: 'Execute file or command', category: 'process', mitreId: 'T1106', aliases: ['ShellExecuteA', 'ShellExecuteW'] },
  { name: 'shellexecuteex', capabilities: ['Process'], riskLevel: 'high', description: 'Execute with extended options', category: 'process', mitreId: 'T1106', aliases: ['ShellExecuteExA', 'ShellExecuteExW'] },
  { name: 'winexec', capabilities: ['Process'], riskLevel: 'critical', description: 'Execute command (legacy)', category: 'process', mitreId: 'T1106' },
  { name: 'system', capabilities: ['Process'], riskLevel: 'critical', description: 'Execute shell command', category: 'process', mitreId: 'T1059' },
  { name: 'popen', capabilities: ['Process'], riskLevel: 'high', description: 'Open pipe to command', category: 'process', mitreId: 'T1059', aliases: ['_popen'] },
  { name: 'execve', capabilities: ['Process'], riskLevel: 'high', description: 'Execute program (Linux)', category: 'process', mitreId: 'T1106' },
  { name: 'execv', capabilities: ['Process'], riskLevel: 'high', description: 'Execute with args array', category: 'process', mitreId: 'T1106' },
  { name: 'execl', capabilities: ['Process'], riskLevel: 'high', description: 'Execute with arg list', category: 'process', mitreId: 'T1106' },
  { name: 'execvp', capabilities: ['Process'], riskLevel: 'high', description: 'Execute with PATH search', category: 'process', mitreId: 'T1106' },
  { name: 'fork', capabilities: ['Process'], riskLevel: 'medium', description: 'Create child process', category: 'process' },
  { name: 'vfork', capabilities: ['Process'], riskLevel: 'medium', description: 'Create child process (efficient)', category: 'process' },
  { name: 'clone', capabilities: ['Process', 'Threading'], riskLevel: 'medium', description: 'Create process/thread', category: 'process' },
  { name: 'posix_spawn', capabilities: ['Process'], riskLevel: 'high', description: 'Spawn new process', category: 'process' },

  // Process manipulation
  { name: 'openprocess', capabilities: ['Process'], riskLevel: 'high', description: 'Open process handle', category: 'process', mitreId: 'T1055' },
  { name: 'terminateprocess', capabilities: ['Process'], riskLevel: 'high', description: 'Terminate process', category: 'process', mitreId: 'T1489' },
  { name: 'exitprocess', capabilities: ['Process'], riskLevel: 'low', description: 'Exit current process', category: 'process' },
  { name: 'getexitcodeprocess', capabilities: ['Process'], riskLevel: 'low', description: 'Get process exit code', category: 'process' },
  { name: 'waitforsingleobject', capabilities: ['Process', 'Threading'], riskLevel: 'low', description: 'Wait for object', category: 'process' },
  { name: 'waitformultipleobjects', capabilities: ['Process', 'Threading'], riskLevel: 'low', description: 'Wait for multiple objects', category: 'process' },
  { name: 'getprocessid', capabilities: ['Process'], riskLevel: 'low', description: 'Get process ID', category: 'process' },
  { name: 'getcurrentprocess', capabilities: ['Process'], riskLevel: 'low', description: 'Get current process handle', category: 'process' },
  { name: 'getcurrentprocessid', capabilities: ['Process'], riskLevel: 'low', description: 'Get current process ID', category: 'process' },
  { name: 'getprocessheap', capabilities: ['Process', 'Memory'], riskLevel: 'low', description: 'Get process heap', category: 'process' },

  // Process enumeration
  { name: 'createtoolhelp32snapshot', capabilities: ['Process', 'System'], riskLevel: 'medium', description: 'Create process snapshot', category: 'process', mitreId: 'T1057' },
  { name: 'process32first', capabilities: ['Process', 'System'], riskLevel: 'medium', description: 'Enumerate first process', category: 'process', mitreId: 'T1057', aliases: ['Process32FirstW'] },
  { name: 'process32next', capabilities: ['Process', 'System'], riskLevel: 'medium', description: 'Enumerate next process', category: 'process', mitreId: 'T1057', aliases: ['Process32NextW'] },
  { name: 'module32first', capabilities: ['Process', 'System'], riskLevel: 'medium', description: 'Enumerate first module', category: 'process', aliases: ['Module32FirstW'] },
  { name: 'module32next', capabilities: ['Process', 'System'], riskLevel: 'medium', description: 'Enumerate next module', category: 'process', aliases: ['Module32NextW'] },
  { name: 'enumprocesses', capabilities: ['Process', 'System'], riskLevel: 'medium', description: 'Enumerate all processes', category: 'process', mitreId: 'T1057' },
  { name: 'enumprocessmodules', capabilities: ['Process', 'System'], riskLevel: 'medium', description: 'Enumerate process modules', category: 'process' },
  { name: 'enumprocessmodulesex', capabilities: ['Process', 'System'], riskLevel: 'medium', description: 'Enumerate modules (extended)', category: 'process' },

  // Module/DLL loading
  { name: 'loadlibrary', capabilities: ['Process'], riskLevel: 'high', description: 'Load DLL into process', category: 'process', mitreId: 'T1129', aliases: ['LoadLibraryA', 'LoadLibraryW'] },
  { name: 'loadlibraryex', capabilities: ['Process'], riskLevel: 'high', description: 'Load DLL with flags', category: 'process', mitreId: 'T1129', aliases: ['LoadLibraryExA', 'LoadLibraryExW'] },
  { name: 'freelibrary', capabilities: ['Process'], riskLevel: 'low', description: 'Unload DLL', category: 'process' },
  { name: 'getmodulehandle', capabilities: ['Process'], riskLevel: 'low', description: 'Get loaded module handle', category: 'process', aliases: ['GetModuleHandleA', 'GetModuleHandleW'] },
  { name: 'getmodulefilename', capabilities: ['Process'], riskLevel: 'low', description: 'Get module file path', category: 'process', aliases: ['GetModuleFileNameA', 'GetModuleFileNameW'] },
  { name: 'getprocaddress', capabilities: ['Process'], riskLevel: 'high', description: 'Get function address', category: 'process', mitreId: 'T1106' },
  { name: 'ldrloaddll', capabilities: ['Process'], riskLevel: 'critical', description: 'Load DLL (NT API)', category: 'process', mitreId: 'T1129' },
  { name: 'ldrunloaddll', capabilities: ['Process'], riskLevel: 'medium', description: 'Unload DLL (NT API)', category: 'process' },
  { name: 'ldrgetprocedureaddress', capabilities: ['Process'], riskLevel: 'high', description: 'Get function (NT API)', category: 'process' },

  // Linux process
  { name: 'dlopen', capabilities: ['Process'], riskLevel: 'high', description: 'Load shared library', category: 'process' },
  { name: 'dlsym', capabilities: ['Process'], riskLevel: 'high', description: 'Get symbol address', category: 'process' },
  { name: 'dlclose', capabilities: ['Process'], riskLevel: 'low', description: 'Close shared library', category: 'process' },
  { name: 'kill', capabilities: ['Process'], riskLevel: 'high', description: 'Send signal to process', category: 'process' },
  { name: 'waitpid', capabilities: ['Process'], riskLevel: 'low', description: 'Wait for child process', category: 'process' },
  { name: 'wait', capabilities: ['Process'], riskLevel: 'low', description: 'Wait for child', category: 'process' },
  { name: 'getpid', capabilities: ['Process'], riskLevel: 'low', description: 'Get process ID', category: 'process' },
  { name: 'getppid', capabilities: ['Process'], riskLevel: 'low', description: 'Get parent process ID', category: 'process' },
  { name: 'setsid', capabilities: ['Process'], riskLevel: 'medium', description: 'Create new session', category: 'process' },
  { name: 'setpgid', capabilities: ['Process'], riskLevel: 'low', description: 'Set process group', category: 'process' },
];

// ============================================================================
// INJECTION FUNCTIONS (~40 functions)
// ============================================================================

const INJECTION_FUNCTIONS: ImportMetadata[] = [
  // Memory allocation in remote process
  { name: 'virtualallocex', capabilities: ['Memory', 'Injection'], riskLevel: 'critical', description: 'Allocate memory in remote process', category: 'injection', mitreId: 'T1055' },
  { name: 'virtualfreeex', capabilities: ['Memory', 'Injection'], riskLevel: 'medium', description: 'Free memory in remote process', category: 'injection' },
  { name: 'virtualprotectex', capabilities: ['Memory', 'Injection'], riskLevel: 'critical', description: 'Change memory protection in remote process', category: 'injection', mitreId: 'T1055' },
  { name: 'virtualqueryex', capabilities: ['Memory'], riskLevel: 'medium', description: 'Query memory in remote process', category: 'injection' },

  // Remote memory read/write
  { name: 'writeprocessmemory', capabilities: ['Memory', 'Injection'], riskLevel: 'critical', description: 'Write to remote process memory', category: 'injection', mitreId: 'T1055' },
  { name: 'readprocessmemory', capabilities: ['Memory'], riskLevel: 'high', description: 'Read remote process memory', category: 'injection', mitreId: 'T1003' },
  { name: 'ntreadprocessmemory', capabilities: ['Memory'], riskLevel: 'high', description: 'Read memory (NT API)', category: 'injection' },
  { name: 'ntwritevirtualmemory', capabilities: ['Memory', 'Injection'], riskLevel: 'critical', description: 'Write memory (NT API)', category: 'injection', mitreId: 'T1055' },

  // Remote thread creation
  { name: 'createremotethread', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Create thread in remote process', category: 'injection', mitreId: 'T1055' },
  { name: 'createremotethreadex', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Create remote thread (extended)', category: 'injection', mitreId: 'T1055' },
  { name: 'ntcreatethreadex', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Create thread (NT API)', category: 'injection', mitreId: 'T1055' },
  { name: 'rtlcreateuserthread', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Create user thread (RTL)', category: 'injection', mitreId: 'T1055' },

  // APC injection
  { name: 'queueuserapc', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Queue APC to thread', category: 'injection', mitreId: 'T1055.004' },
  { name: 'ntqueueapcthread', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Queue APC (NT API)', category: 'injection', mitreId: 'T1055.004' },
  { name: 'ntqueueapcthreadex', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Queue APC extended', category: 'injection', mitreId: 'T1055.004' },

  // Thread context manipulation
  { name: 'getthreadcontext', capabilities: ['Threading'], riskLevel: 'high', description: 'Get thread registers', category: 'injection', mitreId: 'T1055' },
  { name: 'setthreadcontext', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Set thread registers', category: 'injection', mitreId: 'T1055' },
  { name: 'ntgetcontextthread', capabilities: ['Threading'], riskLevel: 'high', description: 'Get context (NT API)', category: 'injection' },
  { name: 'ntsetcontextthread', capabilities: ['Threading', 'Injection'], riskLevel: 'critical', description: 'Set context (NT API)', category: 'injection', mitreId: 'T1055' },
  { name: 'suspendthread', capabilities: ['Threading'], riskLevel: 'medium', description: 'Suspend thread', category: 'injection' },
  { name: 'resumethread', capabilities: ['Threading'], riskLevel: 'medium', description: 'Resume thread', category: 'injection' },
  { name: 'ntsuspendthread', capabilities: ['Threading'], riskLevel: 'medium', description: 'Suspend thread (NT API)', category: 'injection' },
  { name: 'ntresumethread', capabilities: ['Threading'], riskLevel: 'medium', description: 'Resume thread (NT API)', category: 'injection' },

  // Process hollowing
  { name: 'ntunmapviewofsection', capabilities: ['Memory', 'Injection'], riskLevel: 'critical', description: 'Unmap section from process', category: 'injection', mitreId: 'T1055.012' },
  { name: 'zwunmapviewofsection', capabilities: ['Memory', 'Injection'], riskLevel: 'critical', description: 'Unmap section (Zw)', category: 'injection', mitreId: 'T1055.012' },
  { name: 'ntmapviewofsection', capabilities: ['Memory', 'Injection'], riskLevel: 'critical', description: 'Map section into process', category: 'injection', mitreId: 'T1055.012' },
  { name: 'ntcreatesection', capabilities: ['Memory'], riskLevel: 'high', description: 'Create memory section', category: 'injection' },

  // Hook injection
  { name: 'setwindowshookex', capabilities: ['UI', 'Injection'], riskLevel: 'critical', description: 'Install Windows hook', category: 'injection', mitreId: 'T1056.001', aliases: ['SetWindowsHookExA', 'SetWindowsHookExW'] },
  { name: 'unhookwindowshookex', capabilities: ['UI'], riskLevel: 'low', description: 'Remove Windows hook', category: 'injection' },
  { name: 'callnexthookex', capabilities: ['UI'], riskLevel: 'low', description: 'Call next hook', category: 'injection' },

  // DLL injection helpers
  { name: 'ntcreateprocess', capabilities: ['Process'], riskLevel: 'critical', description: 'Create process (NT API)', category: 'injection' },
  { name: 'ntcreateprocessex', capabilities: ['Process'], riskLevel: 'critical', description: 'Create process extended', category: 'injection' },
  { name: 'ntopenprocess', capabilities: ['Process'], riskLevel: 'high', description: 'Open process (NT API)', category: 'injection' },

  // Linux injection
  { name: 'ptrace', capabilities: ['Process', 'AntiDebug'], riskLevel: 'critical', description: 'Process trace/debug', category: 'injection', mitreId: 'T1055.008' },
  { name: 'process_vm_readv', capabilities: ['Memory'], riskLevel: 'high', description: 'Read process memory (Linux)', category: 'injection' },
  { name: 'process_vm_writev', capabilities: ['Memory', 'Injection'], riskLevel: 'critical', description: 'Write process memory (Linux)', category: 'injection' },
];

// ============================================================================
// CRYPTO FUNCTIONS (~60 functions)
// ============================================================================

const CRYPTO_FUNCTIONS: ImportMetadata[] = [
  // Windows CryptoAPI
  { name: 'cryptacquirecontext', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Acquire crypto context', category: 'crypto', aliases: ['CryptAcquireContextA', 'CryptAcquireContextW'] },
  { name: 'cryptreleasecontext', capabilities: ['Crypto'], riskLevel: 'low', description: 'Release crypto context', category: 'crypto' },
  { name: 'cryptgenkey', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Generate crypto key', category: 'crypto' },
  { name: 'cryptderivekey', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Derive key from password', category: 'crypto' },
  { name: 'cryptimportkey', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Import crypto key', category: 'crypto' },
  { name: 'cryptexportkey', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Export crypto key', category: 'crypto' },
  { name: 'cryptdestroykey', capabilities: ['Crypto'], riskLevel: 'low', description: 'Destroy crypto key', category: 'crypto' },
  { name: 'cryptencrypt', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Encrypt data', category: 'crypto', mitreId: 'T1486' },
  { name: 'cryptdecrypt', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Decrypt data', category: 'crypto' },
  { name: 'cryptcreatehash', capabilities: ['Crypto'], riskLevel: 'low', description: 'Create hash object', category: 'crypto' },
  { name: 'crypthashdata', capabilities: ['Crypto'], riskLevel: 'low', description: 'Hash data', category: 'crypto' },
  { name: 'cryptgethashparam', capabilities: ['Crypto'], riskLevel: 'low', description: 'Get hash value', category: 'crypto' },
  { name: 'cryptdestroyhash', capabilities: ['Crypto'], riskLevel: 'low', description: 'Destroy hash object', category: 'crypto' },
  { name: 'cryptsignhash', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Sign hash', category: 'crypto' },
  { name: 'cryptverifysignature', capabilities: ['Crypto'], riskLevel: 'low', description: 'Verify signature', category: 'crypto' },
  { name: 'cryptgenrandom', capabilities: ['Crypto'], riskLevel: 'low', description: 'Generate random bytes', category: 'crypto' },
  { name: 'cryptsetkeyparam', capabilities: ['Crypto'], riskLevel: 'low', description: 'Set key parameter', category: 'crypto' },
  { name: 'cryptgetkeyparam', capabilities: ['Crypto'], riskLevel: 'low', description: 'Get key parameter', category: 'crypto' },

  // CNG (Cryptography Next Generation)
  { name: 'bcryptopenalgorithmprovider', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Open BCrypt provider', category: 'crypto' },
  { name: 'bcryptclosealgorithmprovider', capabilities: ['Crypto'], riskLevel: 'low', description: 'Close BCrypt provider', category: 'crypto' },
  { name: 'bcryptgeneratesymmetrickey', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Generate symmetric key', category: 'crypto' },
  { name: 'bcryptgeneratekeypair', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Generate key pair', category: 'crypto' },
  { name: 'bcryptimportkey', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Import BCrypt key', category: 'crypto' },
  { name: 'bcryptexportkey', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Export BCrypt key', category: 'crypto' },
  { name: 'bcryptdestroykey', capabilities: ['Crypto'], riskLevel: 'low', description: 'Destroy BCrypt key', category: 'crypto' },
  { name: 'bcryptencrypt', capabilities: ['Crypto'], riskLevel: 'medium', description: 'BCrypt encrypt', category: 'crypto', mitreId: 'T1486' },
  { name: 'bcryptdecrypt', capabilities: ['Crypto'], riskLevel: 'medium', description: 'BCrypt decrypt', category: 'crypto' },
  { name: 'bcryptcreatehash', capabilities: ['Crypto'], riskLevel: 'low', description: 'Create BCrypt hash', category: 'crypto' },
  { name: 'bcrypthashdata', capabilities: ['Crypto'], riskLevel: 'low', description: 'BCrypt hash data', category: 'crypto' },
  { name: 'bcryptfinishhash', capabilities: ['Crypto'], riskLevel: 'low', description: 'Finish BCrypt hash', category: 'crypto' },
  { name: 'bcryptdestroyhash', capabilities: ['Crypto'], riskLevel: 'low', description: 'Destroy BCrypt hash', category: 'crypto' },
  { name: 'bcryptsignhash', capabilities: ['Crypto'], riskLevel: 'medium', description: 'BCrypt sign hash', category: 'crypto' },
  { name: 'bcryptverifysignature', capabilities: ['Crypto'], riskLevel: 'low', description: 'BCrypt verify signature', category: 'crypto' },
  { name: 'bcryptgenrandom', capabilities: ['Crypto'], riskLevel: 'low', description: 'BCrypt random bytes', category: 'crypto' },

  // Data Protection API (DPAPI)
  { name: 'cryptprotectdata', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Encrypt with DPAPI', category: 'crypto' },
  { name: 'cryptunprotectdata', capabilities: ['Crypto'], riskLevel: 'high', description: 'Decrypt with DPAPI', category: 'crypto', mitreId: 'T1555' },
  { name: 'cryptprotectmemory', capabilities: ['Crypto', 'Memory'], riskLevel: 'medium', description: 'Encrypt memory', category: 'crypto' },
  { name: 'cryptunprotectmemory', capabilities: ['Crypto', 'Memory'], riskLevel: 'medium', description: 'Decrypt memory', category: 'crypto' },

  // OpenSSL
  { name: 'evp_encryptinit_ex', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Initialize encryption', category: 'crypto' },
  { name: 'evp_encryptupdate', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Encrypt data block', category: 'crypto' },
  { name: 'evp_encryptfinal_ex', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Finalize encryption', category: 'crypto' },
  { name: 'evp_decryptinit_ex', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Initialize decryption', category: 'crypto' },
  { name: 'evp_decryptupdate', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Decrypt data block', category: 'crypto' },
  { name: 'evp_decryptfinal_ex', capabilities: ['Crypto'], riskLevel: 'medium', description: 'Finalize decryption', category: 'crypto' },
  { name: 'evp_digestinit_ex', capabilities: ['Crypto'], riskLevel: 'low', description: 'Initialize digest', category: 'crypto' },
  { name: 'evp_digestupdate', capabilities: ['Crypto'], riskLevel: 'low', description: 'Update digest', category: 'crypto' },
  { name: 'evp_digestfinal_ex', capabilities: ['Crypto'], riskLevel: 'low', description: 'Finalize digest', category: 'crypto' },
  { name: 'rsa_public_encrypt', capabilities: ['Crypto'], riskLevel: 'medium', description: 'RSA public encrypt', category: 'crypto' },
  { name: 'rsa_private_decrypt', capabilities: ['Crypto'], riskLevel: 'medium', description: 'RSA private decrypt', category: 'crypto' },
  { name: 'aes_encrypt', capabilities: ['Crypto'], riskLevel: 'medium', description: 'AES encrypt', category: 'crypto' },
  { name: 'aes_decrypt', capabilities: ['Crypto'], riskLevel: 'medium', description: 'AES decrypt', category: 'crypto' },
  { name: 'rand_bytes', capabilities: ['Crypto'], riskLevel: 'low', description: 'Random bytes', category: 'crypto' },

  // Common C library
  { name: 'md5', capabilities: ['Crypto'], riskLevel: 'low', description: 'MD5 hash', category: 'crypto' },
  { name: 'sha1', capabilities: ['Crypto'], riskLevel: 'low', description: 'SHA1 hash', category: 'crypto' },
  { name: 'sha256', capabilities: ['Crypto'], riskLevel: 'low', description: 'SHA256 hash', category: 'crypto' },
];

// ============================================================================
// ANTI-DEBUG FUNCTIONS (~35 functions)
// ============================================================================

const ANTIDEBUG_FUNCTIONS: ImportMetadata[] = [
  // Debugger detection
  { name: 'isdebuggerpresent', capabilities: ['AntiDebug'], riskLevel: 'high', description: 'Check if debugger attached', category: 'antidebug', mitreId: 'T1622' },
  { name: 'checkremotedebuggerpresent', capabilities: ['AntiDebug'], riskLevel: 'high', description: 'Check for remote debugger', category: 'antidebug', mitreId: 'T1622' },
  { name: 'ntqueryinformationprocess', capabilities: ['AntiDebug', 'System'], riskLevel: 'high', description: 'Query process info (anti-debug)', category: 'antidebug', mitreId: 'T1622' },
  { name: 'ntsetinformationthread', capabilities: ['Threading', 'AntiDebug'], riskLevel: 'high', description: 'Hide thread from debugger', category: 'antidebug', mitreId: 'T1622' },
  { name: 'ntqueryobject', capabilities: ['System', 'AntiDebug'], riskLevel: 'medium', description: 'Query object info', category: 'antidebug' },
  { name: 'ntquerysysteminformation', capabilities: ['System', 'AntiDebug'], riskLevel: 'medium', description: 'Query system info', category: 'antidebug', mitreId: 'T1082' },
  { name: 'ntclose', capabilities: ['AntiDebug'], riskLevel: 'medium', description: 'Close handle (debug detection)', category: 'antidebug' },

  // Debug output/control
  { name: 'outputdebugstring', capabilities: ['AntiDebug'], riskLevel: 'medium', description: 'Output debug string', category: 'antidebug', aliases: ['OutputDebugStringA', 'OutputDebugStringW'] },
  { name: 'debugactiveprocess', capabilities: ['Process', 'AntiDebug'], riskLevel: 'high', description: 'Attach debugger to process', category: 'antidebug' },
  { name: 'debugactiveprocessstop', capabilities: ['Process', 'AntiDebug'], riskLevel: 'medium', description: 'Detach debugger', category: 'antidebug' },
  { name: 'debugbreak', capabilities: ['AntiDebug'], riskLevel: 'medium', description: 'Trigger breakpoint', category: 'antidebug' },
  { name: 'debugsetprocesskillonexit', capabilities: ['Process', 'AntiDebug'], riskLevel: 'medium', description: 'Kill on debugger exit', category: 'antidebug' },

  // Timing checks
  { name: 'gettickcount', capabilities: ['System', 'AntiDebug'], riskLevel: 'low', description: 'Get tick count (timing)', category: 'antidebug' },
  { name: 'gettickcount64', capabilities: ['System', 'AntiDebug'], riskLevel: 'low', description: 'Get tick count 64-bit', category: 'antidebug' },
  { name: 'queryperformancecounter', capabilities: ['System', 'AntiDebug'], riskLevel: 'low', description: 'High-res timer', category: 'antidebug' },
  { name: 'rdtsc', capabilities: ['System', 'AntiDebug'], riskLevel: 'medium', description: 'Read timestamp counter', category: 'antidebug' },

  // VM/Sandbox detection
  { name: 'getdiskfreespace', capabilities: ['System', 'AntiDebug'], riskLevel: 'low', description: 'Check disk space (VM detect)', category: 'antidebug', mitreId: 'T1497', aliases: ['GetDiskFreeSpaceA', 'GetDiskFreeSpaceW'] },
  { name: 'getsystemmetrics', capabilities: ['System', 'AntiDebug'], riskLevel: 'low', description: 'Get system metrics (VM detect)', category: 'antidebug', mitreId: 'T1497' },
  { name: 'enumdisplaydevices', capabilities: ['System', 'AntiDebug'], riskLevel: 'low', description: 'Enumerate displays (VM detect)', category: 'antidebug', mitreId: 'T1497', aliases: ['EnumDisplayDevicesA', 'EnumDisplayDevicesW'] },
  { name: 'getadaptersinfo', capabilities: ['Network', 'AntiDebug'], riskLevel: 'low', description: 'Get network adapters (VM detect)', category: 'antidebug', mitreId: 'T1497' },
  { name: 'getadaptersaddresses', capabilities: ['Network', 'AntiDebug'], riskLevel: 'low', description: 'Get adapter addresses', category: 'antidebug', mitreId: 'T1497' },

  // Exception-based
  { name: 'setunhandledexceptionfilter', capabilities: ['Process', 'AntiDebug'], riskLevel: 'medium', description: 'Set exception handler (anti-debug)', category: 'antidebug', mitreId: 'T1622' },
  { name: 'addvectoredexceptionhandler', capabilities: ['Process', 'AntiDebug'], riskLevel: 'medium', description: 'Add vectored handler', category: 'antidebug' },
  { name: 'raiseexception', capabilities: ['Process', 'AntiDebug'], riskLevel: 'low', description: 'Raise exception', category: 'antidebug' },

  // Linux anti-debug
  { name: 'prctl', capabilities: ['Process', 'AntiDebug'], riskLevel: 'medium', description: 'Process control (anti-ptrace)', category: 'antidebug', mitreId: 'T1622' },
];

// ============================================================================
// REGISTRY FUNCTIONS (~30 functions)
// ============================================================================

const REGISTRY_FUNCTIONS: ImportMetadata[] = [
  // Key operations
  { name: 'regopenkeyex', capabilities: ['Registry'], riskLevel: 'medium', description: 'Open registry key', category: 'registry', aliases: ['RegOpenKeyExA', 'RegOpenKeyExW'] },
  { name: 'regcreatekeyex', capabilities: ['Registry', 'Persistence'], riskLevel: 'high', description: 'Create registry key', category: 'registry', mitreId: 'T1547.001', aliases: ['RegCreateKeyExA', 'RegCreateKeyExW'] },
  { name: 'regdeletekey', capabilities: ['Registry'], riskLevel: 'high', description: 'Delete registry key', category: 'registry', aliases: ['RegDeleteKeyA', 'RegDeleteKeyW'] },
  { name: 'regdeletekeyex', capabilities: ['Registry'], riskLevel: 'high', description: 'Delete key (extended)', category: 'registry', aliases: ['RegDeleteKeyExA', 'RegDeleteKeyExW'] },
  { name: 'regclosekey', capabilities: ['Registry'], riskLevel: 'low', description: 'Close registry key', category: 'registry' },

  // Value operations
  { name: 'regsetvalueex', capabilities: ['Registry', 'Persistence'], riskLevel: 'high', description: 'Set registry value', category: 'registry', mitreId: 'T1547.001', aliases: ['RegSetValueExA', 'RegSetValueExW'] },
  { name: 'regqueryvalueex', capabilities: ['Registry'], riskLevel: 'low', description: 'Query registry value', category: 'registry', aliases: ['RegQueryValueExA', 'RegQueryValueExW'] },
  { name: 'reggetvalue', capabilities: ['Registry'], riskLevel: 'low', description: 'Get registry value', category: 'registry', aliases: ['RegGetValueA', 'RegGetValueW'] },
  { name: 'regdeletevalue', capabilities: ['Registry'], riskLevel: 'medium', description: 'Delete registry value', category: 'registry', aliases: ['RegDeleteValueA', 'RegDeleteValueW'] },

  // Enumeration
  { name: 'regenumkeyex', capabilities: ['Registry', 'System'], riskLevel: 'low', description: 'Enumerate registry keys', category: 'registry', aliases: ['RegEnumKeyExA', 'RegEnumKeyExW'] },
  { name: 'regenumvalue', capabilities: ['Registry', 'System'], riskLevel: 'low', description: 'Enumerate registry values', category: 'registry', aliases: ['RegEnumValueA', 'RegEnumValueW'] },
  { name: 'regqueryinfokey', capabilities: ['Registry'], riskLevel: 'low', description: 'Query key info', category: 'registry', aliases: ['RegQueryInfoKeyA', 'RegQueryInfoKeyW'] },

  // NT API registry
  { name: 'ntopenkey', capabilities: ['Registry'], riskLevel: 'medium', description: 'Open key (NT API)', category: 'registry' },
  { name: 'ntcreatekey', capabilities: ['Registry', 'Persistence'], riskLevel: 'high', description: 'Create key (NT API)', category: 'registry', mitreId: 'T1547.001' },
  { name: 'ntdeletekey', capabilities: ['Registry'], riskLevel: 'high', description: 'Delete key (NT API)', category: 'registry' },
  { name: 'ntsetvaluekey', capabilities: ['Registry', 'Persistence'], riskLevel: 'high', description: 'Set value (NT API)', category: 'registry', mitreId: 'T1547.001' },
  { name: 'ntqueryvaluekey', capabilities: ['Registry'], riskLevel: 'low', description: 'Query value (NT API)', category: 'registry' },
  { name: 'ntdeletevaluekey', capabilities: ['Registry'], riskLevel: 'medium', description: 'Delete value (NT API)', category: 'registry' },
  { name: 'ntenumeratekey', capabilities: ['Registry', 'System'], riskLevel: 'low', description: 'Enumerate keys (NT API)', category: 'registry' },
  { name: 'ntenumeratevaluekey', capabilities: ['Registry', 'System'], riskLevel: 'low', description: 'Enumerate values (NT API)', category: 'registry' },

  // Notification
  { name: 'regnotifychangekeyvalue', capabilities: ['Registry'], riskLevel: 'medium', description: 'Monitor registry changes', category: 'registry' },
];

// ============================================================================
// FILE I/O FUNCTIONS (~70 functions)
// ============================================================================

const FILEIO_FUNCTIONS: ImportMetadata[] = [
  // File creation/opening
  { name: 'createfile', capabilities: ['FileIO'], riskLevel: 'low', description: 'Create or open file', category: 'fileio', aliases: ['CreateFileA', 'CreateFileW'] },
  { name: 'openfile', capabilities: ['FileIO'], riskLevel: 'low', description: 'Open file (legacy)', category: 'fileio' },
  { name: 'closehandle', capabilities: ['FileIO'], riskLevel: 'low', description: 'Close file handle', category: 'fileio' },

  // Read/Write
  { name: 'readfile', capabilities: ['FileIO'], riskLevel: 'low', description: 'Read from file', category: 'fileio' },
  { name: 'readfileex', capabilities: ['FileIO'], riskLevel: 'low', description: 'Read file (async)', category: 'fileio' },
  { name: 'writefile', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Write to file', category: 'fileio' },
  { name: 'writefileex', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Write file (async)', category: 'fileio' },
  { name: 'setfilepointer', capabilities: ['FileIO'], riskLevel: 'low', description: 'Set file position', category: 'fileio' },
  { name: 'setfilepointerex', capabilities: ['FileIO'], riskLevel: 'low', description: 'Set file position (64-bit)', category: 'fileio' },
  { name: 'setendoffile', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Set file size', category: 'fileio' },
  { name: 'flushfilebuffers', capabilities: ['FileIO'], riskLevel: 'low', description: 'Flush file buffers', category: 'fileio' },

  // File operations
  { name: 'deletefile', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Delete file', category: 'fileio', mitreId: 'T1070.004', aliases: ['DeleteFileA', 'DeleteFileW'] },
  { name: 'copyfile', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Copy file', category: 'fileio', aliases: ['CopyFileA', 'CopyFileW'] },
  { name: 'copyfileex', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Copy file (extended)', category: 'fileio', aliases: ['CopyFileExA', 'CopyFileExW'] },
  { name: 'movefile', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Move/rename file', category: 'fileio', aliases: ['MoveFileA', 'MoveFileW'] },
  { name: 'movefileex', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Move file (extended)', category: 'fileio', aliases: ['MoveFileExA', 'MoveFileExW'] },
  { name: 'replacefilew', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Replace file atomically', category: 'fileio' },

  // Directory operations
  { name: 'createdirectory', capabilities: ['FileIO'], riskLevel: 'low', description: 'Create directory', category: 'fileio', aliases: ['CreateDirectoryA', 'CreateDirectoryW'] },
  { name: 'removedirectory', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Remove directory', category: 'fileio', aliases: ['RemoveDirectoryA', 'RemoveDirectoryW'] },
  { name: 'setcurrentdirectory', capabilities: ['FileIO'], riskLevel: 'low', description: 'Change current directory', category: 'fileio', aliases: ['SetCurrentDirectoryA', 'SetCurrentDirectoryW'] },
  { name: 'getcurrentdirectory', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get current directory', category: 'fileio', aliases: ['GetCurrentDirectoryA', 'GetCurrentDirectoryW'] },

  // File enumeration
  { name: 'findfirstfile', capabilities: ['FileIO', 'System'], riskLevel: 'low', description: 'Start file enumeration', category: 'fileio', mitreId: 'T1083', aliases: ['FindFirstFileA', 'FindFirstFileW'] },
  { name: 'findfirstfileex', capabilities: ['FileIO', 'System'], riskLevel: 'low', description: 'Find file (extended)', category: 'fileio', mitreId: 'T1083', aliases: ['FindFirstFileExA', 'FindFirstFileExW'] },
  { name: 'findnextfile', capabilities: ['FileIO', 'System'], riskLevel: 'low', description: 'Continue enumeration', category: 'fileio', mitreId: 'T1083', aliases: ['FindNextFileA', 'FindNextFileW'] },
  { name: 'findclose', capabilities: ['FileIO'], riskLevel: 'low', description: 'Close find handle', category: 'fileio' },

  // File attributes
  { name: 'getfileattributes', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get file attributes', category: 'fileio', aliases: ['GetFileAttributesA', 'GetFileAttributesW'] },
  { name: 'getfileattributesex', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get attributes (extended)', category: 'fileio', aliases: ['GetFileAttributesExA', 'GetFileAttributesExW'] },
  { name: 'setfileattributes', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Set file attributes', category: 'fileio', aliases: ['SetFileAttributesA', 'SetFileAttributesW'] },
  { name: 'getfilesize', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get file size', category: 'fileio' },
  { name: 'getfilesizeex', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get file size (64-bit)', category: 'fileio' },
  { name: 'getfiletime', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get file timestamps', category: 'fileio' },
  { name: 'setfiletime', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Set file timestamps', category: 'fileio', mitreId: 'T1070.006' },
  { name: 'getfiletype', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get file type', category: 'fileio' },

  // Memory-mapped files
  { name: 'createfilemapping', capabilities: ['FileIO', 'Memory'], riskLevel: 'medium', description: 'Create file mapping', category: 'fileio', aliases: ['CreateFileMappingA', 'CreateFileMappingW'] },
  { name: 'openfilemapping', capabilities: ['FileIO', 'Memory'], riskLevel: 'medium', description: 'Open file mapping', category: 'fileio', aliases: ['OpenFileMappingA', 'OpenFileMappingW'] },
  { name: 'mapviewoffile', capabilities: ['FileIO', 'Memory'], riskLevel: 'medium', description: 'Map file into memory', category: 'fileio' },
  { name: 'mapviewoffileex', capabilities: ['FileIO', 'Memory'], riskLevel: 'medium', description: 'Map file (extended)', category: 'fileio' },
  { name: 'unmapviewoffile', capabilities: ['FileIO', 'Memory'], riskLevel: 'low', description: 'Unmap file from memory', category: 'fileio' },

  // Linux/POSIX file I/O
  { name: 'open', capabilities: ['FileIO'], riskLevel: 'low', description: 'Open file (POSIX)', category: 'fileio' },
  { name: 'close', capabilities: ['FileIO'], riskLevel: 'low', description: 'Close file (POSIX)', category: 'fileio' },
  { name: 'read', capabilities: ['FileIO'], riskLevel: 'low', description: 'Read file (POSIX)', category: 'fileio' },
  { name: 'write', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Write file (POSIX)', category: 'fileio' },
  { name: 'lseek', capabilities: ['FileIO'], riskLevel: 'low', description: 'Seek in file', category: 'fileio' },
  { name: 'fopen', capabilities: ['FileIO'], riskLevel: 'low', description: 'Open file stream', category: 'fileio' },
  { name: 'fclose', capabilities: ['FileIO'], riskLevel: 'low', description: 'Close file stream', category: 'fileio' },
  { name: 'fread', capabilities: ['FileIO'], riskLevel: 'low', description: 'Read from stream', category: 'fileio' },
  { name: 'fwrite', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Write to stream', category: 'fileio' },
  { name: 'fseek', capabilities: ['FileIO'], riskLevel: 'low', description: 'Seek in stream', category: 'fileio' },
  { name: 'ftell', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get stream position', category: 'fileio' },
  { name: 'fflush', capabilities: ['FileIO'], riskLevel: 'low', description: 'Flush stream', category: 'fileio' },
  { name: 'stat', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get file status', category: 'fileio' },
  { name: 'fstat', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get file status (fd)', category: 'fileio' },
  { name: 'lstat', capabilities: ['FileIO'], riskLevel: 'low', description: 'Get symlink status', category: 'fileio' },
  { name: 'unlink', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Delete file (POSIX)', category: 'fileio', mitreId: 'T1070.004' },
  { name: 'remove', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Remove file', category: 'fileio' },
  { name: 'rename', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Rename file', category: 'fileio' },
  { name: 'mkdir', capabilities: ['FileIO'], riskLevel: 'low', description: 'Create directory (POSIX)', category: 'fileio' },
  { name: 'rmdir', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Remove directory (POSIX)', category: 'fileio' },
  { name: 'opendir', capabilities: ['FileIO', 'System'], riskLevel: 'low', description: 'Open directory stream', category: 'fileio', mitreId: 'T1083' },
  { name: 'readdir', capabilities: ['FileIO', 'System'], riskLevel: 'low', description: 'Read directory entry', category: 'fileio', mitreId: 'T1083' },
  { name: 'closedir', capabilities: ['FileIO'], riskLevel: 'low', description: 'Close directory stream', category: 'fileio' },
  { name: 'chmod', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Change file mode', category: 'fileio' },
  { name: 'chown', capabilities: ['FileIO'], riskLevel: 'medium', description: 'Change file owner', category: 'fileio' },
  { name: 'mmap', capabilities: ['Memory', 'FileIO'], riskLevel: 'medium', description: 'Map file to memory', category: 'fileio' },
  { name: 'munmap', capabilities: ['Memory'], riskLevel: 'low', description: 'Unmap memory', category: 'fileio' },
];

// ============================================================================
// SERVICE FUNCTIONS (~25 functions)
// ============================================================================

const SERVICE_FUNCTIONS: ImportMetadata[] = [
  { name: 'openscmanager', capabilities: ['System'], riskLevel: 'medium', description: 'Open service manager', category: 'service', aliases: ['OpenSCManagerA', 'OpenSCManagerW'] },
  { name: 'createservice', capabilities: ['System', 'Persistence'], riskLevel: 'critical', description: 'Create Windows service', category: 'service', mitreId: 'T1543.003', aliases: ['CreateServiceA', 'CreateServiceW'] },
  { name: 'openservice', capabilities: ['System'], riskLevel: 'medium', description: 'Open service handle', category: 'service', aliases: ['OpenServiceA', 'OpenServiceW'] },
  { name: 'deleteservice', capabilities: ['System'], riskLevel: 'high', description: 'Delete service', category: 'service' },
  { name: 'startservice', capabilities: ['System'], riskLevel: 'high', description: 'Start service', category: 'service', aliases: ['StartServiceA', 'StartServiceW'] },
  { name: 'controlservice', capabilities: ['System'], riskLevel: 'high', description: 'Control service', category: 'service', mitreId: 'T1489' },
  { name: 'queryservicestatus', capabilities: ['System'], riskLevel: 'low', description: 'Query service status', category: 'service' },
  { name: 'queryservicestatusex', capabilities: ['System'], riskLevel: 'low', description: 'Query status (extended)', category: 'service' },
  { name: 'queryserviceconfig', capabilities: ['System'], riskLevel: 'low', description: 'Query service config', category: 'service', aliases: ['QueryServiceConfigA', 'QueryServiceConfigW'] },
  { name: 'changeserviceconfig', capabilities: ['System', 'Persistence'], riskLevel: 'high', description: 'Change service config', category: 'service', mitreId: 'T1543.003', aliases: ['ChangeServiceConfigA', 'ChangeServiceConfigW'] },
  { name: 'enumservicesstatus', capabilities: ['System'], riskLevel: 'low', description: 'Enumerate services', category: 'service', aliases: ['EnumServicesStatusA', 'EnumServicesStatusW'] },
  { name: 'enumservicesstatusex', capabilities: ['System'], riskLevel: 'low', description: 'Enumerate (extended)', category: 'service', aliases: ['EnumServicesStatusExA', 'EnumServicesStatusExW'] },
  { name: 'closeservicehandle', capabilities: ['System'], riskLevel: 'low', description: 'Close service handle', category: 'service' },
  { name: 'startservicectrldispatcher', capabilities: ['System'], riskLevel: 'medium', description: 'Start service dispatcher', category: 'service', aliases: ['StartServiceCtrlDispatcherA', 'StartServiceCtrlDispatcherW'] },
  { name: 'registerservicectrlhandler', capabilities: ['System'], riskLevel: 'low', description: 'Register control handler', category: 'service', aliases: ['RegisterServiceCtrlHandlerA', 'RegisterServiceCtrlHandlerW'] },
  { name: 'setservicestatus', capabilities: ['System'], riskLevel: 'medium', description: 'Set service status', category: 'service' },
];

// ============================================================================
// CREDENTIAL FUNCTIONS (~25 functions)
// ============================================================================

const CREDENTIAL_FUNCTIONS: ImportMetadata[] = [
  // Windows Credential Manager
  { name: 'credenumerate', capabilities: ['System'], riskLevel: 'critical', description: 'Enumerate stored credentials', category: 'credential', mitreId: 'T1555', aliases: ['CredEnumerateA', 'CredEnumerateW'] },
  { name: 'credread', capabilities: ['System'], riskLevel: 'critical', description: 'Read stored credential', category: 'credential', mitreId: 'T1555', aliases: ['CredReadA', 'CredReadW'] },
  { name: 'credwrite', capabilities: ['System'], riskLevel: 'high', description: 'Write credential', category: 'credential', aliases: ['CredWriteA', 'CredWriteW'] },
  { name: 'creddelete', capabilities: ['System'], riskLevel: 'medium', description: 'Delete credential', category: 'credential', aliases: ['CredDeleteA', 'CredDeleteW'] },
  { name: 'credfree', capabilities: ['System'], riskLevel: 'low', description: 'Free credential memory', category: 'credential' },
  { name: 'credgetinfo', capabilities: ['System'], riskLevel: 'medium', description: 'Get credential info', category: 'credential' },

  // LSA
  { name: 'lsaopenpolicy', capabilities: ['System'], riskLevel: 'high', description: 'Open LSA policy', category: 'credential', mitreId: 'T1003' },
  { name: 'lsalookupsids', capabilities: ['System'], riskLevel: 'medium', description: 'Lookup SIDs', category: 'credential' },
  { name: 'lsalookupnames', capabilities: ['System'], riskLevel: 'medium', description: 'Lookup names', category: 'credential', aliases: ['LsaLookupNames2'] },
  { name: 'lsaenumeratelogonsessions', capabilities: ['System'], riskLevel: 'high', description: 'Enumerate logon sessions', category: 'credential', mitreId: 'T1003' },
  { name: 'lsagetlogonsessiondata', capabilities: ['System'], riskLevel: 'high', description: 'Get logon session data', category: 'credential', mitreId: 'T1003' },

  // Token manipulation
  { name: 'openprocesstoken', capabilities: ['Process'], riskLevel: 'high', description: 'Open process token', category: 'credential', mitreId: 'T1134' },
  { name: 'openthreadtoken', capabilities: ['Threading'], riskLevel: 'high', description: 'Open thread token', category: 'credential', mitreId: 'T1134' },
  { name: 'duplicatetokenex', capabilities: ['Process'], riskLevel: 'critical', description: 'Duplicate token', category: 'credential', mitreId: 'T1134' },
  { name: 'impersonateloggedonuser', capabilities: ['Process'], riskLevel: 'critical', description: 'Impersonate user', category: 'credential', mitreId: 'T1134' },
  { name: 'setthreadtoken', capabilities: ['Threading'], riskLevel: 'critical', description: 'Set thread token', category: 'credential', mitreId: 'T1134' },
  { name: 'adjusttokenprivileges', capabilities: ['Process'], riskLevel: 'critical', description: 'Adjust token privileges', category: 'credential', mitreId: 'T1134' },
  { name: 'lookupprivilegevalue', capabilities: ['System'], riskLevel: 'medium', description: 'Lookup privilege', category: 'credential', aliases: ['LookupPrivilegeValueA', 'LookupPrivilegeValueW'] },
  { name: 'gettokeninformation', capabilities: ['Process'], riskLevel: 'medium', description: 'Get token info', category: 'credential' },

  // Logon functions
  { name: 'logonuser', capabilities: ['System'], riskLevel: 'critical', description: 'Logon with credentials', category: 'credential', mitreId: 'T1078', aliases: ['LogonUserA', 'LogonUserW'] },
  { name: 'logonuserex', capabilities: ['System'], riskLevel: 'critical', description: 'Logon (extended)', category: 'credential', mitreId: 'T1078', aliases: ['LogonUserExA', 'LogonUserExW'] },
];

// ============================================================================
// MEMORY FUNCTIONS (~35 functions)
// ============================================================================

const MEMORY_FUNCTIONS: ImportMetadata[] = [
  // Virtual memory
  { name: 'virtualalloc', capabilities: ['Memory'], riskLevel: 'medium', description: 'Allocate virtual memory', category: 'memory' },
  { name: 'virtualfree', capabilities: ['Memory'], riskLevel: 'low', description: 'Free virtual memory', category: 'memory' },
  { name: 'virtualprotect', capabilities: ['Memory'], riskLevel: 'high', description: 'Change memory protection', category: 'memory', mitreId: 'T1055' },
  { name: 'virtualquery', capabilities: ['Memory'], riskLevel: 'low', description: 'Query memory info', category: 'memory' },
  { name: 'virtuallock', capabilities: ['Memory'], riskLevel: 'low', description: 'Lock memory pages', category: 'memory' },
  { name: 'virtualunlock', capabilities: ['Memory'], riskLevel: 'low', description: 'Unlock memory pages', category: 'memory' },

  // NT memory
  { name: 'ntallocatevirtualmemory', capabilities: ['Memory'], riskLevel: 'medium', description: 'Allocate memory (NT)', category: 'memory' },
  { name: 'ntfreevirtualmemory', capabilities: ['Memory'], riskLevel: 'low', description: 'Free memory (NT)', category: 'memory' },
  { name: 'ntprotectvirtualmemory', capabilities: ['Memory'], riskLevel: 'high', description: 'Protect memory (NT)', category: 'memory' },
  { name: 'ntqueryvirtualmemory', capabilities: ['Memory'], riskLevel: 'low', description: 'Query memory (NT)', category: 'memory' },

  // Heap
  { name: 'heapcreate', capabilities: ['Memory'], riskLevel: 'low', description: 'Create heap', category: 'memory' },
  { name: 'heapdestroy', capabilities: ['Memory'], riskLevel: 'low', description: 'Destroy heap', category: 'memory' },
  { name: 'heapalloc', capabilities: ['Memory'], riskLevel: 'low', description: 'Allocate from heap', category: 'memory' },
  { name: 'heaprealloc', capabilities: ['Memory'], riskLevel: 'low', description: 'Reallocate heap', category: 'memory' },
  { name: 'heapfree', capabilities: ['Memory'], riskLevel: 'low', description: 'Free heap memory', category: 'memory' },
  { name: 'heapsize', capabilities: ['Memory'], riskLevel: 'low', description: 'Get allocation size', category: 'memory' },

  // C library
  { name: 'malloc', capabilities: ['Memory'], riskLevel: 'low', description: 'Allocate memory', category: 'memory' },
  { name: 'calloc', capabilities: ['Memory'], riskLevel: 'low', description: 'Allocate zeroed memory', category: 'memory' },
  { name: 'realloc', capabilities: ['Memory'], riskLevel: 'low', description: 'Reallocate memory', category: 'memory' },
  { name: 'free', capabilities: ['Memory'], riskLevel: 'low', description: 'Free memory', category: 'memory' },
  { name: 'memcpy', capabilities: ['Memory'], riskLevel: 'low', description: 'Copy memory', category: 'memory' },
  { name: 'memmove', capabilities: ['Memory'], riskLevel: 'low', description: 'Move memory', category: 'memory' },
  { name: 'memset', capabilities: ['Memory'], riskLevel: 'low', description: 'Fill memory', category: 'memory' },
  { name: 'memcmp', capabilities: ['Memory'], riskLevel: 'low', description: 'Compare memory', category: 'memory' },

  // Linux memory
  { name: 'mprotect', capabilities: ['Memory'], riskLevel: 'high', description: 'Change memory protection (Linux)', category: 'memory', mitreId: 'T1055' },
  { name: 'brk', capabilities: ['Memory'], riskLevel: 'low', description: 'Change data segment size', category: 'memory' },
  { name: 'sbrk', capabilities: ['Memory'], riskLevel: 'low', description: 'Increment data segment', category: 'memory' },
];

// ============================================================================
// UI/KEYLOGGER FUNCTIONS (~30 functions)
// ============================================================================

const UI_KEYLOGGER_FUNCTIONS: ImportMetadata[] = [
  // Keyboard hooks (keylogging)
  { name: 'getasynckeystate', capabilities: ['UI'], riskLevel: 'critical', description: 'Get async key state (keylogger)', category: 'keylogger', mitreId: 'T1056.001' },
  { name: 'getkeystate', capabilities: ['UI'], riskLevel: 'high', description: 'Get key state', category: 'keylogger', mitreId: 'T1056.001' },
  { name: 'getkeyboardstate', capabilities: ['UI'], riskLevel: 'high', description: 'Get keyboard state', category: 'keylogger', mitreId: 'T1056.001' },
  { name: 'mapvirtualkey', capabilities: ['UI'], riskLevel: 'medium', description: 'Map virtual key code', category: 'keylogger', aliases: ['MapVirtualKeyA', 'MapVirtualKeyW'] },
  { name: 'getkeyboardlayout', capabilities: ['UI'], riskLevel: 'low', description: 'Get keyboard layout', category: 'keylogger' },
  { name: 'getkeyboardlayoutname', capabilities: ['UI'], riskLevel: 'low', description: 'Get layout name', category: 'keylogger', aliases: ['GetKeyboardLayoutNameA', 'GetKeyboardLayoutNameW'] },

  // Clipboard
  { name: 'openclipboard', capabilities: ['UI'], riskLevel: 'medium', description: 'Open clipboard', category: 'clipboard', mitreId: 'T1115' },
  { name: 'closeclipboard', capabilities: ['UI'], riskLevel: 'low', description: 'Close clipboard', category: 'clipboard' },
  { name: 'getclipboarddata', capabilities: ['UI'], riskLevel: 'high', description: 'Get clipboard data', category: 'clipboard', mitreId: 'T1115' },
  { name: 'setclipboarddata', capabilities: ['UI'], riskLevel: 'medium', description: 'Set clipboard data', category: 'clipboard' },
  { name: 'emptyclipboard', capabilities: ['UI'], riskLevel: 'medium', description: 'Clear clipboard', category: 'clipboard' },
  { name: 'isclipboardformatavailable', capabilities: ['UI'], riskLevel: 'low', description: 'Check clipboard format', category: 'clipboard' },

  // Window manipulation
  { name: 'findwindow', capabilities: ['UI'], riskLevel: 'medium', description: 'Find window by name', category: 'ui', aliases: ['FindWindowA', 'FindWindowW'] },
  { name: 'findwindowex', capabilities: ['UI'], riskLevel: 'medium', description: 'Find window (extended)', category: 'ui', aliases: ['FindWindowExA', 'FindWindowExW'] },
  { name: 'getforegroundwindow', capabilities: ['UI'], riskLevel: 'medium', description: 'Get foreground window', category: 'ui', mitreId: 'T1056.001' },
  { name: 'getwindowtext', capabilities: ['UI'], riskLevel: 'medium', description: 'Get window title', category: 'ui', aliases: ['GetWindowTextA', 'GetWindowTextW'] },
  { name: 'setforegroundwindow', capabilities: ['UI'], riskLevel: 'medium', description: 'Set foreground window', category: 'ui' },
  { name: 'showwindow', capabilities: ['UI'], riskLevel: 'low', description: 'Show/hide window', category: 'ui' },
  { name: 'enumwindows', capabilities: ['UI', 'System'], riskLevel: 'low', description: 'Enumerate windows', category: 'ui' },
  { name: 'enumchildwindows', capabilities: ['UI'], riskLevel: 'low', description: 'Enumerate child windows', category: 'ui' },
  { name: 'getwindowthreadprocessid', capabilities: ['UI', 'Process'], riskLevel: 'medium', description: 'Get window process ID', category: 'ui' },

  // Screenshot capture
  { name: 'bitblt', capabilities: ['UI'], riskLevel: 'high', description: 'Bit block transfer (screenshot)', category: 'screenshot', mitreId: 'T1113' },
  { name: 'stretchblt', capabilities: ['UI'], riskLevel: 'high', description: 'Stretch blit (screenshot)', category: 'screenshot', mitreId: 'T1113' },
  { name: 'getdc', capabilities: ['UI'], riskLevel: 'medium', description: 'Get device context', category: 'screenshot' },
  { name: 'getwindowdc', capabilities: ['UI'], riskLevel: 'medium', description: 'Get window DC', category: 'screenshot' },
  { name: 'releasedc', capabilities: ['UI'], riskLevel: 'low', description: 'Release device context', category: 'screenshot' },
  { name: 'createcompatibledc', capabilities: ['UI'], riskLevel: 'medium', description: 'Create compatible DC', category: 'screenshot' },
  { name: 'createcompatiblebitmap', capabilities: ['UI'], riskLevel: 'medium', description: 'Create bitmap', category: 'screenshot' },
  { name: 'selectobject', capabilities: ['UI'], riskLevel: 'low', description: 'Select GDI object', category: 'screenshot' },
  { name: 'getdibits', capabilities: ['UI'], riskLevel: 'high', description: 'Get bitmap bits (screenshot)', category: 'screenshot', mitreId: 'T1113' },
];

// ============================================================================
// SYSTEM INFO FUNCTIONS (~25 functions)
// ============================================================================

const SYSTEM_INFO_FUNCTIONS: ImportMetadata[] = [
  { name: 'getsysteminfo', capabilities: ['System'], riskLevel: 'low', description: 'Get system information', category: 'sysinfo', mitreId: 'T1082' },
  { name: 'getnativesysteminfo', capabilities: ['System'], riskLevel: 'low', description: 'Get native system info', category: 'sysinfo', mitreId: 'T1082' },
  { name: 'getversion', capabilities: ['System'], riskLevel: 'low', description: 'Get OS version (legacy)', category: 'sysinfo', mitreId: 'T1082' },
  { name: 'getversionex', capabilities: ['System'], riskLevel: 'low', description: 'Get OS version extended', category: 'sysinfo', mitreId: 'T1082', aliases: ['GetVersionExA', 'GetVersionExW'] },
  { name: 'rtlgetversion', capabilities: ['System'], riskLevel: 'low', description: 'Get version (NT)', category: 'sysinfo', mitreId: 'T1082' },
  { name: 'getcomputername', capabilities: ['System'], riskLevel: 'low', description: 'Get computer name', category: 'sysinfo', mitreId: 'T1082', aliases: ['GetComputerNameA', 'GetComputerNameW'] },
  { name: 'getcomputernameex', capabilities: ['System'], riskLevel: 'low', description: 'Get computer name (extended)', category: 'sysinfo', aliases: ['GetComputerNameExA', 'GetComputerNameExW'] },
  { name: 'getusername', capabilities: ['System'], riskLevel: 'low', description: 'Get current username', category: 'sysinfo', mitreId: 'T1033', aliases: ['GetUserNameA', 'GetUserNameW'] },
  { name: 'getmodulefilename', capabilities: ['Process'], riskLevel: 'low', description: 'Get module path', category: 'sysinfo', aliases: ['GetModuleFileNameA', 'GetModuleFileNameW'] },
  { name: 'getsystemdirectory', capabilities: ['System'], riskLevel: 'low', description: 'Get system directory', category: 'sysinfo', aliases: ['GetSystemDirectoryA', 'GetSystemDirectoryW'] },
  { name: 'getwindowsdirectory', capabilities: ['System'], riskLevel: 'low', description: 'Get Windows directory', category: 'sysinfo', aliases: ['GetWindowsDirectoryA', 'GetWindowsDirectoryW'] },
  { name: 'gettemppath', capabilities: ['System'], riskLevel: 'low', description: 'Get temp directory', category: 'sysinfo', aliases: ['GetTempPathA', 'GetTempPathW'] },
  { name: 'getenvironmentvariable', capabilities: ['System'], riskLevel: 'low', description: 'Get environment variable', category: 'sysinfo', aliases: ['GetEnvironmentVariableA', 'GetEnvironmentVariableW'] },
  { name: 'setenvironmentvariable', capabilities: ['System'], riskLevel: 'medium', description: 'Set environment variable', category: 'sysinfo', aliases: ['SetEnvironmentVariableA', 'SetEnvironmentVariableW'] },
  { name: 'getlocaleinfo', capabilities: ['System'], riskLevel: 'low', description: 'Get locale info', category: 'sysinfo', aliases: ['GetLocaleInfoA', 'GetLocaleInfoW'] },
  { name: 'getsystemtime', capabilities: ['System'], riskLevel: 'low', description: 'Get system time', category: 'sysinfo' },
  { name: 'getlocaltime', capabilities: ['System'], riskLevel: 'low', description: 'Get local time', category: 'sysinfo' },
  { name: 'getsystemtimeasfiletime', capabilities: ['System'], riskLevel: 'low', description: 'Get time as FILETIME', category: 'sysinfo' },

  // Linux
  { name: 'uname', capabilities: ['System'], riskLevel: 'low', description: 'Get system info (Linux)', category: 'sysinfo', mitreId: 'T1082' },
  { name: 'sysinfo', capabilities: ['System'], riskLevel: 'low', description: 'Get memory/uptime info', category: 'sysinfo' },
  { name: 'getenv', capabilities: ['System'], riskLevel: 'low', description: 'Get environment variable', category: 'sysinfo' },
  { name: 'setenv', capabilities: ['System'], riskLevel: 'medium', description: 'Set environment variable', category: 'sysinfo' },
  { name: 'gethostname', capabilities: ['System', 'Network'], riskLevel: 'low', description: 'Get hostname', category: 'sysinfo', mitreId: 'T1082' },
  { name: 'getuid', capabilities: ['System'], riskLevel: 'low', description: 'Get user ID', category: 'sysinfo' },
  { name: 'geteuid', capabilities: ['System'], riskLevel: 'low', description: 'Get effective user ID', category: 'sysinfo' },
  { name: 'getpwuid', capabilities: ['System'], riskLevel: 'low', description: 'Get user info by UID', category: 'sysinfo', mitreId: 'T1033' },
  { name: 'getpwnam', capabilities: ['System'], riskLevel: 'low', description: 'Get user info by name', category: 'sysinfo' },
];

// ============================================================================
// THREADING FUNCTIONS (~25 functions)
// ============================================================================

const THREADING_FUNCTIONS: ImportMetadata[] = [
  { name: 'createthread', capabilities: ['Threading'], riskLevel: 'low', description: 'Create thread', category: 'threading' },
  { name: 'openthread', capabilities: ['Threading'], riskLevel: 'medium', description: 'Open thread handle', category: 'threading' },
  { name: 'terminatethread', capabilities: ['Threading'], riskLevel: 'medium', description: 'Terminate thread', category: 'threading' },
  { name: 'exitthread', capabilities: ['Threading'], riskLevel: 'low', description: 'Exit current thread', category: 'threading' },
  { name: 'getcurrentthread', capabilities: ['Threading'], riskLevel: 'low', description: 'Get current thread', category: 'threading' },
  { name: 'getcurrentthreadid', capabilities: ['Threading'], riskLevel: 'low', description: 'Get current thread ID', category: 'threading' },
  { name: 'getthreadid', capabilities: ['Threading'], riskLevel: 'low', description: 'Get thread ID', category: 'threading' },
  { name: 'getexitcodethread', capabilities: ['Threading'], riskLevel: 'low', description: 'Get thread exit code', category: 'threading' },
  { name: 'setthreadpriority', capabilities: ['Threading'], riskLevel: 'low', description: 'Set thread priority', category: 'threading' },
  { name: 'getthreadpriority', capabilities: ['Threading'], riskLevel: 'low', description: 'Get thread priority', category: 'threading' },
  { name: 'sleep', capabilities: ['Threading'], riskLevel: 'low', description: 'Sleep current thread', category: 'threading' },
  { name: 'sleepex', capabilities: ['Threading'], riskLevel: 'low', description: 'Sleep (alertable)', category: 'threading' },
  { name: 'switchtothread', capabilities: ['Threading'], riskLevel: 'low', description: 'Yield to other thread', category: 'threading' },

  // Thread Local Storage
  { name: 'tlsalloc', capabilities: ['Threading'], riskLevel: 'low', description: 'Allocate TLS index', category: 'threading' },
  { name: 'tlsfree', capabilities: ['Threading'], riskLevel: 'low', description: 'Free TLS index', category: 'threading' },
  { name: 'tlssetvalue', capabilities: ['Threading'], riskLevel: 'low', description: 'Set TLS value', category: 'threading' },
  { name: 'tlsgetvalue', capabilities: ['Threading'], riskLevel: 'low', description: 'Get TLS value', category: 'threading' },

  // Synchronization
  { name: 'createevent', capabilities: ['Threading'], riskLevel: 'low', description: 'Create event object', category: 'threading', aliases: ['CreateEventA', 'CreateEventW'] },
  { name: 'setevent', capabilities: ['Threading'], riskLevel: 'low', description: 'Set event', category: 'threading' },
  { name: 'resetevent', capabilities: ['Threading'], riskLevel: 'low', description: 'Reset event', category: 'threading' },
  { name: 'createmutex', capabilities: ['Threading'], riskLevel: 'low', description: 'Create mutex', category: 'threading', aliases: ['CreateMutexA', 'CreateMutexW'] },
  { name: 'releasemutex', capabilities: ['Threading'], riskLevel: 'low', description: 'Release mutex', category: 'threading' },
  { name: 'createsemaphore', capabilities: ['Threading'], riskLevel: 'low', description: 'Create semaphore', category: 'threading', aliases: ['CreateSemaphoreA', 'CreateSemaphoreW'] },
  { name: 'releasesemaphore', capabilities: ['Threading'], riskLevel: 'low', description: 'Release semaphore', category: 'threading' },
  { name: 'initializecriticalsection', capabilities: ['Threading'], riskLevel: 'low', description: 'Init critical section', category: 'threading' },
  { name: 'entercriticalsection', capabilities: ['Threading'], riskLevel: 'low', description: 'Enter critical section', category: 'threading' },
  { name: 'leavecriticalsection', capabilities: ['Threading'], riskLevel: 'low', description: 'Leave critical section', category: 'threading' },
  { name: 'deletecriticalsection', capabilities: ['Threading'], riskLevel: 'low', description: 'Delete critical section', category: 'threading' },

  // POSIX threads
  { name: 'pthread_create', capabilities: ['Threading'], riskLevel: 'low', description: 'Create POSIX thread', category: 'threading' },
  { name: 'pthread_join', capabilities: ['Threading'], riskLevel: 'low', description: 'Join POSIX thread', category: 'threading' },
  { name: 'pthread_exit', capabilities: ['Threading'], riskLevel: 'low', description: 'Exit POSIX thread', category: 'threading' },
  { name: 'pthread_mutex_init', capabilities: ['Threading'], riskLevel: 'low', description: 'Init POSIX mutex', category: 'threading' },
  { name: 'pthread_mutex_lock', capabilities: ['Threading'], riskLevel: 'low', description: 'Lock POSIX mutex', category: 'threading' },
  { name: 'pthread_mutex_unlock', capabilities: ['Threading'], riskLevel: 'low', description: 'Unlock POSIX mutex', category: 'threading' },
];

// ============================================================================
// POPULATE DATABASE
// ============================================================================

function populateDatabase(): void {
  const allFunctions = [
    ...NETWORK_FUNCTIONS,
    ...PROCESS_FUNCTIONS,
    ...INJECTION_FUNCTIONS,
    ...CRYPTO_FUNCTIONS,
    ...ANTIDEBUG_FUNCTIONS,
    ...REGISTRY_FUNCTIONS,
    ...FILEIO_FUNCTIONS,
    ...SERVICE_FUNCTIONS,
    ...CREDENTIAL_FUNCTIONS,
    ...MEMORY_FUNCTIONS,
    ...UI_KEYLOGGER_FUNCTIONS,
    ...SYSTEM_INFO_FUNCTIONS,
    ...THREADING_FUNCTIONS,
  ];

  for (const func of allFunctions) {
    // Add main name (lowercase)
    IMPORT_DATABASE.set(func.name.toLowerCase(), func);

    // Add aliases
    if (func.aliases) {
      for (const alias of func.aliases) {
        IMPORT_DATABASE.set(alias.toLowerCase(), func);
      }
    }
  }
}

// Initialize database
populateDatabase();

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Get metadata for an import function
 */
export function getImportMetadata(importName: string): ImportMetadata | null {
  return IMPORT_DATABASE.get(importName.toLowerCase()) || null;
}

/**
 * Categorize imports by capability
 */
export function categorizeImportsByCapability(imports: string[]): Map<ImportCapability, string[]> {
  const result = new Map<ImportCapability, string[]>();

  for (const imp of imports) {
    const metadata = getImportMetadata(imp);
    if (metadata) {
      for (const cap of metadata.capabilities) {
        const existing = result.get(cap) || [];
        existing.push(imp);
        result.set(cap, existing);
      }
    }
  }

  return result;
}

/**
 * Assess overall risk from imports
 */
export function assessImportRisk(imports: string[]): {
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  riskFactors: string[];
  score: number;
} {
  let score = 0;
  const riskFactors: string[] = [];
  const riskWeights = { low: 1, medium: 2, high: 5, critical: 10 };

  for (const imp of imports) {
    const metadata = getImportMetadata(imp);
    if (metadata) {
      score += riskWeights[metadata.riskLevel];

      if (metadata.riskLevel === 'critical') {
        riskFactors.push(`Critical: ${imp} - ${metadata.description}`);
      } else if (metadata.riskLevel === 'high') {
        riskFactors.push(`High: ${imp} - ${metadata.description}`);
      }
    }
  }

  let overallRisk: 'low' | 'medium' | 'high' | 'critical';
  if (score >= 50) {
    overallRisk = 'critical';
  } else if (score >= 25) {
    overallRisk = 'high';
  } else if (score >= 10) {
    overallRisk = 'medium';
  } else {
    overallRisk = 'low';
  }

  return { overallRisk, riskFactors, score };
}

/**
 * Get imports by category
 */
export function getImportsByCategory(imports: string[], category: string): ImportMetadata[] {
  const result: ImportMetadata[] = [];

  for (const imp of imports) {
    const metadata = getImportMetadata(imp);
    if (metadata && metadata.category === category) {
      result.push(metadata);
    }
  }

  return result;
}

/**
 * Get MITRE ATT&CK techniques from imports
 */
export function getMITRETechniquesFromImports(imports: string[]): Map<string, string[]> {
  const result = new Map<string, string[]>();

  for (const imp of imports) {
    const metadata = getImportMetadata(imp);
    if (metadata && metadata.mitreId) {
      const existing = result.get(metadata.mitreId) || [];
      existing.push(imp);
      result.set(metadata.mitreId, existing);
    }
  }

  return result;
}

/**
 * Get database statistics
 */
export function getDatabaseStats(): {
  totalFunctions: number;
  byCategory: Record<string, number>;
  byRisk: Record<string, number>;
  withMitre: number;
} {
  const uniqueFunctions = new Set<string>();
  const byCategory: Record<string, number> = {};
  const byRisk: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  let withMitre = 0;

  IMPORT_DATABASE.forEach((metadata) => {
    if (uniqueFunctions.has(metadata.name)) return;
    uniqueFunctions.add(metadata.name);

    byCategory[metadata.category] = (byCategory[metadata.category] || 0) + 1;
    byRisk[metadata.riskLevel] = (byRisk[metadata.riskLevel] || 0) + 1;
    if (metadata.mitreId) withMitre++;
  });

  return {
    totalFunctions: uniqueFunctions.size,
    byCategory,
    byRisk,
    withMitre,
  };
}

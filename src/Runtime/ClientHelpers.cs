using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;
using SharpHound.Enums;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHound.Core.Behavior
{
    public class ClientHelpers
    {
        private const string NullKey = "NULLDOMAIN";
        private static readonly HashSet<string> Groups = new HashSet<string> { "268435456", "268435457", "536870912", "536870913" };
        private static readonly HashSet<string> Computers = new HashSet<string> { "805306369" };
        private static readonly HashSet<string> Users = new HashSet<string> { "805306368" };
        private static readonly ConcurrentDictionary<string, DirectorySearcher> DirectorySearchMap = new ConcurrentDictionary<string, DirectorySearcher>();
        private static readonly ConcurrentDictionary<string, LookupClient> DNSResolverCache = new ConcurrentDictionary<string, LookupClient>();
        private static readonly ConcurrentDictionary<string, bool> PingCache = new ConcurrentDictionary<string, bool>();
        private static readonly Random RandomGen = new Random();
        private static readonly CancellationTokenSource CancellationTokenSource = new CancellationTokenSource();
        private static readonly Regex DCReplaceRegex = new Regex("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        internal static readonly string[] ResolutionProps = { "samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname", "msds-groupmsamembership" };

        private static readonly Regex SPNRegex = new Regex(@".*\/.*", RegexOptions.Compiled);
        private static readonly string ProcStartTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        private static string _currentLoopTime = $"{DateTime.Now:yyyyMMddHHmmss}";

        internal static CancellationToken GetCancellationToken()
        {
            return CancellationTokenSource.Token;
        }

        internal static void InvokeCancellation()
        {
            CancellationTokenSource.Cancel();
        }

        /// <summary>
        /// Set some variables, and clear the ping cache for a new run
        /// </summary>
        internal static void StartNewRun()
        {
            PingCache.Clear();
            _currentLoopTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        }

        /// <summary>
        /// Converts a string SID to its hex representation
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        internal static string ConvertSidToHexSid(string sid)
        {
            var securityIdentifier = new SecurityIdentifier(sid);
            var sidBytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sidBytes, 0);

            var output = $"\\{BitConverter.ToString(sidBytes).Replace('-', '\\')}";
            return output;
        }

        /// <summary>
        /// Gets a domain name from a distinguished name
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        internal static string DistinguishedNameToDomain(string distinguishedName)
        {
            var temp = distinguishedName.Substring(distinguishedName.IndexOf("DC=",
                StringComparison.CurrentCultureIgnoreCase));
            temp = DCReplaceRegex.Replace(temp, "").Replace(",", ".").ToUpper();
            return temp;
        }

        /// <summary>
        /// Tries to create a security identifier from a byte array
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        internal static SecurityIdentifier CreateSecurityIdentifier(byte[] sid)
        {
            try
            {
                return new SecurityIdentifier(sid, 0);
            }
            catch (ArgumentException e)
            {
                Console.WriteLine(e.ToString());
                Console.WriteLine($"Failed to create SID from {sid}. Please report this to the developer");
                return null;
            }
        }

        /// <summary>
        /// Gets the name of the forest associate with the domain
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        internal static string GetForestName(string domain = null)
        {
            try
            {
                if (domain == null)
                    return Forest.GetCurrentForest().Name;

                var domainObject = Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, domain));
                return domainObject.Forest.Name;
            }
            catch
            {
                return domain;
            }

        }

        /// <summary>
        /// Converts a SamAccountType property to the appropriate type enum
        /// </summary>
        /// <param name="samAccountType"></param>
        /// <returns></returns>
        internal static Label SamAccountTypeToType(string samAccountType)
        {
            if (Groups.Contains(samAccountType))
                return Label.Group;

            if (Users.Contains(samAccountType))
                return Label.User;

            if (Computers.Contains(samAccountType))
                return Label.Computer;

            return Label.Base; // TODO: double check this
        }

        internal static DirectorySearcher GetDirectorySearcher(string domain)
        {
            var key = NormalizeDomainName(domain) ?? NullKey;
            if (DirectorySearchMap.TryGetValue(key, out var searcher))
                return searcher;

            searcher = new DirectorySearcher(key);
            DirectorySearchMap.TryAdd(key, searcher);
            return searcher;
        }

        /// <summary>
        /// Strips a serviceprincipalname entry down to just its hostname
        /// </summary>
        /// <param name="target"></param>
        /// <returns></returns>
        internal static string StripSPN(string target)
        {
            return SPNRegex.IsMatch(target) ? target.Split('/')[1].Split(':')[0] : target;
        }

        /// <summary>
        /// Prepends a common sid with the domain prefix, or just returns the sid back
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <returns>Prepended SID or same sid</returns>
        internal static string ConvertCommonSid(string sid, string domain)
        {
            if (WellKnownPrincipal.GetWellKnownPrincipal(sid, out _))
            {
                if (sid == "S-1-5-9")
                {
                    var forest = GetForestName(domain);
                    return $"{forest}-{sid}".ToUpper();
                }

                var nDomain = NormalizeDomainName(domain);
                if (sid != "S-1-1-0" && sid != "S-1-5-11")
                    OutputTasks.SeenCommonPrincipals.TryAdd(nDomain, sid);
                return $"{nDomain}-{sid}";
            }

            return sid;
        }

        /// <summary>
        /// Gets a DNS Resolver for a domain, pointing DNS to a DC with port 53 open
        /// </summary>
        /// <param name="domain"></param>
        /// <returns>Resolver</returns>
        internal static LookupClient GetDNSResolver(string domain)
        {
            var domainName = NormalizeDomainName(domain);
            var key = domainName ?? NullKey;

            if (DNSResolverCache.TryGetValue(key, out var resolver))
                return resolver;

            // Create a new resolver object which will auto populate with our local nameservers
            resolver = new LookupClient();

            var newServerList = new List<IPEndPoint>();

            // Try to find a DC in our target domain that has 53 open
            var dnsServer = FindDomainDNSServer(domainName);
            if (dnsServer != null)
            {
                // Resolve the DC to an IP and add it to our nameservers
                var query = resolver.Query(dnsServer, QueryType.A);
                var resolved = query.Answers.ARecords().DefaultIfEmpty(null).FirstOrDefault(record => record.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;
                if (resolved != null)
                    newServerList.Add(new IPEndPoint(resolved, 53));
            }

            newServerList.AddRange(resolver.NameServers.Select(server => server.Endpoint));


            resolver = new LookupClient(newServerList.ToArray());
            DNSResolverCache.TryAdd(key, resolver);
            return resolver;
        }

        /// <summary>
        /// Finds a domain controller serving DNS in the target domain
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        private static string FindDomainDNSServer(Context context, string domain)
        {
            var searcher = GetDirectorySearcher(domain);
            domain = NormalizeDomainName(domain);
            string target = null;
            //Find all DCs in the target domain
            foreach (var result in context.LDAPUtils.QueryLDAP(
                "(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", SearchScope.Subtree,
                new[] { "samaccountname", "dnshostname" }))
            {

                target = result.GetProperty("dnshostname") ?? result.GetProperty("samaccountname");
                if (target == null)
                    continue;

                target = $"{target}.{domain}";
                if (CheckHostPort(target, 53))
                    break;

                target = null;
            }

            return target;
        }

        /// <summary>
        /// Does throttle and jitter for computer requests
        /// </summary>
        /// <returns></returns>
        internal static async Task DoDelay(Context context)
        {
            if (context.Throttle == 0)
                return;

            if (context.Jitter == 0)
            {
                await Task.Delay(context.Throttle);
                return;
            }

            var percent = (int)Math.Floor((double)(context.Jitter * (context.Throttle / 100)));
            var delay = context.Throttle + RandomGen.Next(-percent, percent);
            await Task.Delay(delay);
        }

        /// <summary>
        /// Wrapper for the port scan function that checks caching and other options
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        internal static bool CheckPort(Context context, string hostname, int port)
        {
            if (context.Flags.SkipPortScan)
                return true;

            var key = $"{hostname}-{port}".ToUpper();
            if (PingCache.TryGetValue(key, out var portOpen)) return portOpen;

            portOpen = CheckHostPort(hostname, port);
            PingCache.TryAdd(key, portOpen);
            return portOpen;
        }

        /// <summary>
        /// Checks if a specified port is available on the hostname
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        private static bool CheckHostPort(Context context, string hostname, int port)
        {
            using (var client = new TcpClient())
            {
                try
                {
                    var result = client.BeginConnect(hostname, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(context.PortScanTimeout);
                    if (!success) return false;

                    client.EndConnect(result);
                }
                catch
                {
                    return false;
                }

                return true;
            }
        }

        /// <summary>
        /// Normalizes a domain name to its full DNS name
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        internal static string NormalizeDomainName(string domain)
        {
            var resolved = domain;

            if (resolved.Contains("."))
                return domain.ToUpper();

            resolved = ResolutionHelpers.ResolveDomainNetbiosToDns(domain) ?? domain;

            return resolved.ToUpper();
        }

        /// <summary>
        /// Creates a filename for the looped results which will contain the results of all loops
        /// </summary>
        /// <returns></returns>
        internal static string GetLoopFileName(Context context)
        {
            var finalFilename = context.ZipFilename == null ? "BloodHoundLoopResults.zip" : $"{context.ZipFilename}.zip";

            if (context.Flags.RandomizeFilenames)
            {
                finalFilename = $"{Path.GetRandomFileName()}.zip";
            }

            finalFilename = $"{ProcStartTime}_{finalFilename}";

            if (context.OutputPrefix != null)
            {
                finalFilename = $"{context.OutputPrefix}_{finalFilename}";
            }

            var finalPath = Path.Combine(context.OutputDirectory, finalFilename);

            return finalPath;
        }

        /// <summary>
        /// Uses specified options to determine the final filename of the given file
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="extension"></param>
        /// <param name="addTimestamp"></param>
        /// <returns></returns>
        internal static string ResolveFileName(Context context, string filename, string extension, bool addTimestamp)
        {
            var finalFilename = filename;
            if (!filename.EndsWith(extension))
                finalFilename = $"{filename}.{extension}";

            if ((extension == "json" || extension == "zip") && context.Flags.RandomizeFilenames)
            {
                finalFilename = $"{Path.GetRandomFileName()}";
            }

            if (addTimestamp)
            {
                finalFilename = $"{_currentLoopTime}_{finalFilename}";
            }

            if (context.OutputPrefix != null)
            {
                finalFilename = $"{context.OutputPrefix}_{finalFilename}";
            }

            var finalPath = Path.Combine(context.OutputDirectory, finalFilename);

            return finalPath;
        }

        /// <summary>
        /// Converts a string to its base64 representation
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        internal static string Base64(string input)
        {
            var plainBytes = Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(plainBytes);
        }


        #region NetAPI PInvoke Calls
        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetWkstaGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint level,
            out IntPtr bufPtr);

#pragma warning disable 649
        private struct WorkstationInfo100
        {

            public int platform_id;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string computer_name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }
#pragma warning restore 649

        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetApiBufferFree(IntPtr Buffer);
        #endregion

        #region DsGetDcName

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string SiteName,
            [MarshalAs(UnmanagedType.U4)]
            DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [Flags]
        private enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }

        #endregion

        #region TranslateName

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int TranslateName(string accountName, EXTENDED_NAME_FORMAT accountNameFormat,
            EXTENDED_NAME_FORMAT desiredFormat, StringBuilder translatedName, ref int userNameSize);

        private enum EXTENDED_NAME_FORMAT : int
        {
            /// <summary>
            /// Unknown Name Format
            /// </summary>
            NameUnknown = 0,
            /// <summary>
            /// DistinguishedName Format
            /// CN=Jeff Smith,OU=Users,DC=Engineering,DC=Microsoft,DC=Com
            /// </summary>
            NameFullyQualifiedDN = 1,
            NameSamCompatible = 2, //Engineering\JSmith
            NameDisplay = 3, //Jeff Smith
            /// <summary>
            /// ObjectGUID
            /// {4fa050f0-f561-11cf-bdd9-00aa003a77b6}
            /// </summary>
            NameUniqueId = 6,
            NameCanonical = 7, //engineering.microsoft.com/software/someone
            NameUserPrincipal = 8, //someone@example.com
            NameCanonicalEx = 9, //engineering.microsoft.com/software\nJSmith
            NameServicePrincipal = 10, //www/www.microsoft.com@microsoft.com
            /// <summary>
            /// DnsDomain Format
            /// DOMAIN\SamAccountName
            /// </summary>
            NameDnsDomain = 12

        }
        #endregion

        #region LookupAccountSid

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool LookupAccountSid(
            string lpSystemName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            System.Text.StringBuilder lpName,
            ref uint cchName,
            System.Text.StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse);

        #endregion

        #region LookupAccountName

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupAccountName(string systemName, string accountName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint sidLength, StringBuilder domainName,
            ref uint domainNameLength, out SID_NAME_USE type);

        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }
        #endregion
    }
}
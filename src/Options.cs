using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CommandLine;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using SharpHoundCommonLib.Enums;

namespace Sharphound
{
    public class Options
    {
        // Options that affect what is collected
        [Option('c', "collectionmethods", Default = new[] { "Default" },
            HelpText =
                "Collection Methods: Group, LocalGroup, LocalAdmin, RDP, DCOM, PSRemote, Session, Trusts, ACL, Container, ComputerOnly, GPOLocalGroup, LoggedOn, ObjectProps, SPNTargets, UserRights, Default, DCOnly, All")]
        public IEnumerable<string> CollectionMethods { get; set; }

        [Option('d', "domain", Default = null, HelpText = "Specify domain to enumerate")]
        public string Domain { get; set; }

        [Option('s', "searchforest", Default = false, HelpText = "Search all available domains in the forest")]
        public bool SearchForest { get; set; }
        [Option("recursedomains", Default = false, HelpText = "Recurse domain trusts to search")]
        public bool RecurseDomains { get; set; }

        [Option(HelpText = "Stealth Collection (Prefer DCOnly whenever possible!)")]
        public bool Stealth { get; set; }

        [Option('f', "ldapfilter", HelpText = "Add an LDAP filter to the pregenerated filter.", Default = null)]
        public string LdapFilter { get; set; }

        [Option(HelpText = "Base DistinguishedName to start the LDAP search at", Default = null)]
        public string DistinguishedName { get; set; }

        [Option(HelpText = "Path to file containing computer names to enumerate", Default = null)]
        public string ComputerFile { get; set; }

        // Options that affect output of SharpHound
        [Option(HelpText = "Directory to output file too", Default = ".")]
        public string OutputDirectory { get; set; }

        [Option(HelpText = "String to prepend to output file names")]
        public string OutputPrefix { get; set; }

        [Option(HelpText = "Filename for cache (Defaults to a machine specific identifier)", Default = null)]
        public string CacheName { get; set; }

        [Option(HelpText = "Keep cache in memory and don't write to disk")]
        public bool MemCache { get; set; }

        [Option(HelpText = "Rebuild cache and remove all entries", Default = false)]
        public bool RebuildCache { get; set; }

        [Option(HelpText = "Use random filenames for output", Default = false)]
        public bool RandomFileNames { get; set; }

        [Option(HelpText = "Filename for the zip", Default = null)]
        public string ZipFilename { get; set; }

        [Option(HelpText = "Don't zip files", Default = false)]
        public bool NoZip { get; set; }
        
        [Option(HelpText = "Password protects the zip with the specified password", Default = null)]
        public string ZipPassword { get; set; }

        [Option(HelpText = "Adds a CSV tracking requests to computers", Default = false)]
        public bool TrackComputerCalls { get; set; }

        [Option(HelpText = "Pretty print JSON", Default = false)]
        public bool PrettyPrint { get; set; }

        // Connection options
        [Option(HelpText = "Username for LDAP", Default = null)]
        public string LDAPUsername { get; set; }

        [Option(HelpText = "Password for LDAP", Default = null)]
        public string LDAPPassword { get; set; }

        [Option(HelpText = "Do the session enumeration with local admin credentials instead of domain credentials", Default = false)]
        public bool DoLocalAdminSessionEnum { get; set; }

        [Option(HelpText = "Username for local Administrator to be used if DoLocalAdminSessionEnum is set", Default = null)]
        public string LocalAdminUsername { get; set; }

        [Option(HelpText = "Password for local Administrator to be used if DoLocalAdminSessionEnum is set", Default = null)]
        public string LocalAdminPassword { get; set; }

        [Option(HelpText = "Override domain controller to pull LDAP from. This option can result in data loss", Default = null)]
        public string DomainController { get; set; }

        [Option(HelpText = "Override port for LDAP", Default = 0)]
        public int LDAPPort { get; set; }

        [Option(HelpText = "Connect to LDAP SSL instead of regular LDAP", Default = false)]
        public bool SecureLDAP { get; set; }
        
        [Option(HelpText = "Disables certificate verification when using LDAPS", Default = false)]
        public bool DisableCertVerification { get; set; }

        [Option(HelpText = "Disables Kerberos Signing/Sealing", Default = false)]
        public bool DisableSigning { get; set; }

        //Options that affect how enumeration is performed
        [Option(HelpText = "Skip checking if 445 is open", Default = false)]
        public bool SkipPortCheck { get; set; }
        
        [Option(HelpText = "Timeout for port checks in milliseconds", Default = 500)]
        public int PortCheckTimeout { get; set; }
        
        [Option(HelpText = "Skip check for PwdLastSet when enumerating computers", Default = false)]
        public bool SkipPasswordCheck { get; set; }

        [Option(HelpText = "Exclude domain controllers from session/localgroup enumeration (mostly for ATA/ATP)",
            Default = false)]
        public bool ExcludeDCs { get; set; }

        [Option(HelpText = "Add a delay after computer requests in milliseconds")]
        public int Throttle { get; set; }

        [Option(HelpText = "Add jitter to throttle (percent)")]
        public int Jitter { get; set; }

        [Option('t',"threads", HelpText = "Number of threads to run enumeration with", Default = 50)]
        public int Threads { get; set; }

        [Option(HelpText = "Skip registry session enumeration")]
        public bool SkipRegistryLoggedOn { get; set; }

        [Option(HelpText = "Override the username to filter for NetSessionEnum", Default = null)]
        public string OverrideUserName { get; set; }

        [Option(HelpText = "Override DNS suffix for API calls")]
        public string RealDNSName { get; set; }

        [Option(HelpText = "Collect all LDAP properties from objects")]
        public bool CollectAllProperties { get; set; }

        //Loop Options
        [Option('l', "Loop", HelpText = "Loop computer collection")]
        public bool Loop { get; set; }

        [Option(HelpText="Loop duration (hh:mm:ss - 05:00:00 is 5 hours, default: 2 hrs)")]
        public TimeSpan LoopDuration { get; set; }

        [Option(HelpText="Add delay between loops (hh:mm:ss - 00:03:00 is 3 minutes)")] public TimeSpan LoopInterval { get; set; }

        //Misc Options
        [Option(HelpText = "Interval in which to display status in milliseconds", Default = 30000)]
        public int StatusInterval { get; set; }

        [Option('v', HelpText = "Enable verbose output", Default = (int)LogLevel.Information)]
        public int Verbosity { get; set; }

        internal bool ResolveCollectionMethods(ILogger logger, out ResolvedCollectionMethod resolved, out bool dconly)
        {
            var arr = CollectionMethods.Count() == 1
                ? CollectionMethods.First().Split(',')
                : CollectionMethods.ToArray();

            resolved = ResolvedCollectionMethod.None;
            dconly = false;

            foreach (var baseMethod in arr)
            {
                CollectionMethodOptions option;
                try
                {
                    option = (CollectionMethodOptions)Enum.Parse(typeof(CollectionMethodOptions), baseMethod, true);
                }
                catch
                {
                    logger.LogCritical("Failed to parse collection method {baseMethod}", baseMethod);
                    return false;
                }

                resolved |= option switch
                {
                    CollectionMethodOptions.Group => ResolvedCollectionMethod.Group,
                    CollectionMethodOptions.Session => ResolvedCollectionMethod.Session,
                    CollectionMethodOptions.LoggedOn => ResolvedCollectionMethod.LoggedOn,
                    CollectionMethodOptions.Trusts => ResolvedCollectionMethod.Trusts,
                    CollectionMethodOptions.ACL => ResolvedCollectionMethod.ACL,
                    CollectionMethodOptions.ObjectProps => ResolvedCollectionMethod.ObjectProps,
                    CollectionMethodOptions.RDP => ResolvedCollectionMethod.RDP,
                    CollectionMethodOptions.DCOM => ResolvedCollectionMethod.DCOM,
                    CollectionMethodOptions.LocalAdmin => ResolvedCollectionMethod.LocalAdmin,
                    CollectionMethodOptions.PSRemote => ResolvedCollectionMethod.PSRemote,
                    CollectionMethodOptions.SPNTargets => ResolvedCollectionMethod.SPNTargets,
                    CollectionMethodOptions.Container => ResolvedCollectionMethod.Container,
                    CollectionMethodOptions.GPOLocalGroup => ResolvedCollectionMethod.GPOLocalGroup,
                    CollectionMethodOptions.LocalGroup => ResolvedCollectionMethod.LocalGroups,
                    CollectionMethodOptions.UserRights => ResolvedCollectionMethod.UserRights,
                    CollectionMethodOptions.Default => ResolvedCollectionMethod.Default,
                    CollectionMethodOptions.DCOnly => ResolvedCollectionMethod.DCOnly,
                    CollectionMethodOptions.ComputerOnly => ResolvedCollectionMethod.ComputerOnly,
                    CollectionMethodOptions.All => ResolvedCollectionMethod.All,
                    CollectionMethodOptions.None => ResolvedCollectionMethod.None,
                    _ => throw new ArgumentOutOfRangeException()
                };

                if (option == CollectionMethodOptions.DCOnly) dconly = true;
            }

            if (Stealth)
            {
                var updates = new List<string>();
                if ((resolved & ResolvedCollectionMethod.LoggedOn) != 0)
                {
                    resolved ^= ResolvedCollectionMethod.LoggedOn;
                    updates.Add("[-] Removed LoggedOn");
                }

                var localGroupRemoved = false;
                if ((resolved & ResolvedCollectionMethod.RDP) != 0)
                {
                    localGroupRemoved = true;
                    resolved ^= ResolvedCollectionMethod.RDP;
                    updates.Add("[-] Removed RDP Collection");
                }

                if ((resolved & ResolvedCollectionMethod.DCOM) != 0)
                {
                    localGroupRemoved = true;
                    resolved ^= ResolvedCollectionMethod.DCOM;
                    updates.Add("[-] Removed DCOM Collection");
                }

                if ((resolved & ResolvedCollectionMethod.PSRemote) != 0)
                {
                    localGroupRemoved = true;
                    resolved ^= ResolvedCollectionMethod.PSRemote;
                    updates.Add("[-] Removed PSRemote Collection");
                }

                if ((resolved & ResolvedCollectionMethod.LocalAdmin) != 0)
                {
                    localGroupRemoved = true;
                    resolved ^= ResolvedCollectionMethod.LocalAdmin;
                    updates.Add("[-] Removed LocalAdmin Collection");
                }

                if (localGroupRemoved)
                {
                    resolved |= ResolvedCollectionMethod.GPOLocalGroup;
                    updates.Add("[+] Added GPOLocalGroup");
                }

                if (updates.Count > 0)
                {
                    var updateString = new StringBuilder();
                    updateString.AppendLine("Updated Collection Methods to Reflect Stealth Options");
                    foreach (var update in updates) updateString.AppendLine(update);
                    logger.LogInformation("{Update}", updateString.ToString());
                }
            }

            logger.LogInformation("Resolved Collection Methods: {resolved}", resolved.GetIndividualFlags());
            return true;
        }
    }
}

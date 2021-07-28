
using System;
using BHECollector;
using SharpHound.LdapWrappers;

namespace SharpHound
{
    /// <summary>
    /// Helper class to deal with Well Known SIDs
    /// </summary>
    internal class CommonPrincipal
    {
        private string _principalName;

        internal LdapTypeEnum Type { get; set; }

        /// <summary>
        /// Setter to ensure that the principal name is always upper case
        /// </summary>
        internal string Name
        {
            get => _principalName;
            set => _principalName = value.ToUpper();
        }

        public CommonPrincipal(string name, LdapTypeEnum type)
        {
            Name = name;
            Type = type;
        }

        /// <summary>
        /// Gets the principal associate with a well known SID
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="commonPrincipal"></param>
        /// <returns>True if SID matches a well known principal, false otherwise</returns>
        public static bool GetCommonSid(string sid, out CommonPrincipal commonPrincipal)
        {
            throw new NotImplementedException();
            // switch (sid)
            // {
            //     case "S-1-0":
            //         commonPrincipal = new CommonPrincipal("Null Authority", User);
            //         break;
            //     case "S-1-0-0":
            //         commonPrincipal = new CommonPrincipal("Nobody", User);
            //         break;
            //     case "S-1-1":
            //         commonPrincipal = new CommonPrincipal("World Authority", User);
            //         break;
            //     case "S-1-1-0":
            //         commonPrincipal = new CommonPrincipal("Everyone", Group);
            //         break;
            //     case "S-1-2":
            //         commonPrincipal = new CommonPrincipal("Local Authority", User);
            //         break;
            //     case "S-1-2-0":
            //         commonPrincipal = new CommonPrincipal("Local", Group);
            //         break;
            //     case "S-1-2-1":
            //         commonPrincipal = new CommonPrincipal("Console Logon", Group);
            //         break;
            //     case "S-1-3":
            //         commonPrincipal = new CommonPrincipal("Creator Authority", User);
            //         break;
            //     case "S-1-3-0":
            //         commonPrincipal = new CommonPrincipal("Creator Owner", User);
            //         break;
            //     case "S-1-3-1":
            //         commonPrincipal = new CommonPrincipal("Creator Group", Group);
            //         break;
            //     case "S-1-3-2":
            //         commonPrincipal = new CommonPrincipal("Creator Owner Server", Computer);
            //         break;
            //     case "S-1-3-3":
            //         commonPrincipal = new CommonPrincipal("Creator Group Server", Computer);
            //         break;
            //     case "S-1-3-4":
            //         commonPrincipal = new CommonPrincipal("Owner Rights", Group);
            //         break;
            //     case "S-1-4":
            //         commonPrincipal = new CommonPrincipal("Non-unique Authority", User);
            //         break;
            //     case "S-1-5":
            //         commonPrincipal = new CommonPrincipal("NT Authority", User);
            //         break;
            //     case "S-1-5-1":
            //         commonPrincipal = new CommonPrincipal("Dialup", Group);
            //         break;
            //     case "S-1-5-2":
            //         commonPrincipal = new CommonPrincipal("Network", Group);
            //         break;
            //     case "S-1-5-3":
            //         commonPrincipal = new CommonPrincipal("Batch", Group);
            //         break;
            //     case "S-1-5-4":
            //         commonPrincipal = new CommonPrincipal("Interactive", Group);
            //         break;
            //     case "S-1-5-6":
            //         commonPrincipal = new CommonPrincipal("Service", Group);
            //         break;
            //     case "S-1-5-7":
            //         commonPrincipal = new CommonPrincipal("Anonymous", Group);
            //         break;
            //     case "S-1-5-8":
            //         commonPrincipal = new CommonPrincipal("Proxy", Group);
            //         break;
            //     case "S-1-5-9":
            //         commonPrincipal = new CommonPrincipal("Enterprise Domain Controllers", Group);
            //         break;
            //     case "S-1-5-10":
            //         commonPrincipal = new CommonPrincipal("Principal Self", User);
            //         break;
            //     case "S-1-5-11":
            //         commonPrincipal = new CommonPrincipal("Authenticated Users", Group);
            //         break;
            //     case "S-1-5-12":
            //         commonPrincipal = new CommonPrincipal("Restricted Code", Group);
            //         break;
            //     case "S-1-5-13":
            //         commonPrincipal = new CommonPrincipal("Terminal Server Users", Group);
            //         break;
            //     case "S-1-5-14":
            //         commonPrincipal = new CommonPrincipal("Remote Interactive Logon", Group);
            //         break;
            //     case "S-1-5-15":
            //         commonPrincipal = new CommonPrincipal("This Organization ", Group);
            //         break;
            //     case "S-1-5-17":
            //         commonPrincipal = new CommonPrincipal("This Organization ", Group);
            //         break;
            //     case "S-1-5-18":
            //         commonPrincipal = new CommonPrincipal("Local System", User);
            //         break;
            //     case "S-1-5-19":
            //         commonPrincipal = new CommonPrincipal("NT Authority", User);
            //         break;
            //     case "S-1-5-20":
            //         commonPrincipal = new CommonPrincipal("NT Authority", User);
            //         break;
            //     case "S-1-5-113":
            //         commonPrincipal = new CommonPrincipal("Local Account", User);
            //         break;
            //     case "S-1-5-114":
            //         commonPrincipal = new CommonPrincipal("Local Account and Member of Administrators Group", User);
            //         break;
            //     case "S-1-5-80-0":
            //         commonPrincipal = new CommonPrincipal("All Services ", Group);
            //         break;
            //     case "S-1-5-32-544":
            //         commonPrincipal = new CommonPrincipal("Administrators", Group);
            //         break;
            //     case "S-1-5-32-545":
            //         commonPrincipal = new CommonPrincipal("Users", Group);
            //         break;
            //     case "S-1-5-32-546":
            //         commonPrincipal = new CommonPrincipal("Guests", Group);
            //         break;
            //     case "S-1-5-32-547":
            //         commonPrincipal = new CommonPrincipal("Power Users", Group);
            //         break;
            //     case "S-1-5-32-548":
            //         commonPrincipal = new CommonPrincipal("Account Operators", Group);
            //         break;
            //     case "S-1-5-32-549":
            //         commonPrincipal = new CommonPrincipal("Server Operators", Group);
            //         break;
            //     case "S-1-5-32-550":
            //         commonPrincipal = new CommonPrincipal("Print Operators", Group);
            //         break;
            //     case "S-1-5-32-551":
            //         commonPrincipal = new CommonPrincipal("Backup Operators", Group);
            //         break;
            //     case "S-1-5-32-552":
            //         commonPrincipal = new CommonPrincipal("Replicators", Group);
            //         break;
            //     case "S-1-5-32-554":
            //         commonPrincipal = new CommonPrincipal("Pre-Windows 2000 Compatible Access", Group);
            //         break;
            //     case "S-1-5-32-555":
            //         commonPrincipal = new CommonPrincipal("Remote Desktop Users", Group);
            //         break;
            //     case "S-1-5-32-556":
            //         commonPrincipal = new CommonPrincipal("Network Configuration Operators", Group);
            //         break;
            //     case "S-1-5-32-557":
            //         commonPrincipal = new CommonPrincipal("Incoming Forest Trust Builders", Group);
            //         break;
            //     case "S-1-5-32-558":
            //         commonPrincipal = new CommonPrincipal("Performance Monitor Users", Group);
            //         break;
            //     case "S-1-5-32-559":
            //         commonPrincipal = new CommonPrincipal("Performance Log Users", Group);
            //         break;
            //     case "S-1-5-32-560":
            //         commonPrincipal = new CommonPrincipal("Windows Authorization Access Group", Group);
            //         break;
            //     case "S-1-5-32-561":
            //         commonPrincipal = new CommonPrincipal("Terminal Server License Servers", Group);
            //         break;
            //     case "S-1-5-32-562":
            //         commonPrincipal = new CommonPrincipal("Distributed COM Users", Group);
            //         break;
            //     case "S-1-5-32-568":
            //         commonPrincipal = new CommonPrincipal("IIS_IUSRS", Group);
            //         break;
            //     case "S-1-5-32-569":
            //         commonPrincipal = new CommonPrincipal("Cryptographic Operators", Group);
            //         break;
            //     case "S-1-5-32-573":
            //         commonPrincipal = new CommonPrincipal("Event Log Readers", Group);
            //         break;
            //     case "S-1-5-32-574":
            //         commonPrincipal = new CommonPrincipal("Certificate Service DCOM Access", Group);
            //         break;
            //     case "S-1-5-32-575":
            //         commonPrincipal = new CommonPrincipal("RDS Remote Access Servers", Group);
            //         break;
            //     case "S-1-5-32-576":
            //         commonPrincipal = new CommonPrincipal("RDS Endpoint Servers", Group);
            //         break;
            //     case "S-1-5-32-577":
            //         commonPrincipal = new CommonPrincipal("RDS Management Servers", Group);
            //         break;
            //     case "S-1-5-32-578":
            //         commonPrincipal = new CommonPrincipal("Hyper-V Administrators", Group);
            //         break;
            //     case "S-1-5-32-579":
            //         commonPrincipal = new CommonPrincipal("Access Control Assistance Operators", Group);
            //         break;
            //     case "S-1-5-32-580":
            //         commonPrincipal = new CommonPrincipal("Remote Management Users", Group);
            //         break;
            //     default:
            //         commonPrincipal = null;
            //         break;

            //}

            //return commonPrincipal != null;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHoundCommonLib;

namespace SharpHound.Tasks
{
    internal class SPNTasks
    {
        internal static async Task<LdapWrapper> ProcessSPNS(LdapWrapper wrapper)
        {
            if (wrapper is User user)
            {
                await ProcessUserSPNs(user);
            }

            return wrapper;
        }

        private static async Task ProcessUserSPNs(Context context, User user)
        {
            var servicePrincipalNames = user.SearchResult.GetPropertyAsArray("serviceprincipalname");
            var domain = user.Domain;
            var resolved = new List<SPNTarget>();

            //Loop over the spns, and look for any that start with mssqlsvc
            foreach (var spn in servicePrincipalNames.Where(x => x.StartsWith("mssqlsvc", StringComparison.OrdinalIgnoreCase)))
            {
                int port;
                if (spn.Contains(":"))
                {
                    var success = int.TryParse(spn.Split(':')[1], out port);
                    if (!success)
                        port = 1433;
                }
                else
                {
                    port = 1433;
                }

                //Try to turn the host into a SID
                var hostSid = (spn, domain);
                if (hostSid.StartsWith("S-1-5"))
                {
                    resolved.Add(new SPNTarget
                    {
                        ComputerSid = hostSid,
                        Port = port,
                        Service = "SQLAdmin"
                    });
                }
            }

            user.SPNTargets = resolved.Distinct().ToArray();
        }
    }
}

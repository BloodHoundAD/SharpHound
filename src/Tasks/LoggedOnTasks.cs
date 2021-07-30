using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHound.Tasks
{
    /// <summary>
    /// Tasks for privileged session enumeration
    /// </summary>
    internal class LoggedOnTasks
    {
        private static readonly Regex SidRegex = new Regex(@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$", RegexOptions.Compiled);

        /// <summary>
        /// Entrypoint for the pipeline
        /// </summary>
        /// <param name="wrapper"></param>
        /// <returns></returns>
        internal static async Task<LdapWrapper> ProcessLoggedOn(LdapWrapper wrapper)
        {
            if (wrapper is Computer computer)
            {
                //Make sure we're targetting a windows or non-contactable computer
                if (computer.IsWindows && !computer.PingFailed)
                {
                    var sessions = new List<Session>();
                    sessions.AddRange(await GetLoggedOnUsersAPI(computer));
                    //sessions.AddRange(await GetLoggedOnUsersRegistry(computer));
                    var temp = computer.Sessions.ToList();
                    temp.AddRange(sessions);
                    computer.Sessions = temp.Distinct().ToArray();
                }
            }

            await Helpers.DoDelay();

            return wrapper;
        }

        /// <summary>
        /// Wraps the NetWkstaUserEnum API call in a timeout
        /// </summary>
        /// <param name="computer"></param>
        /// <returns></returns>
        private static async Task<List<Session>> GetLoggedOnUsersAPI(Context context, Computer computer)
        {
            var resumeHandle = 0;
            var workstationInfoType = typeof(WKSTA_USER_INFO_1);
            var ptrInfo = IntPtr.Zero;
            var entriesRead = 0;
            var sessionList = new List<Session>();

            try
            {
                var task = Task.Run(() => NetWkstaUserEnum(computer.APIName, 1, out ptrInfo,
                    -1, out entriesRead, out _, ref resumeHandle));

                if (await Task.WhenAny(task, Task.Delay(10000)) != task)
                {
                    if (context.Flags.DumpComputerStatus)
                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = "Timeout",
                            Task = "NetWkstaUserEnum"
                        });

                    return sessionList;
                }

                var taskResult = task.Result;
                //Check the result of the task. 234 and 0 are both acceptable.
                if (taskResult != 0 && taskResult != 234)
                {
                    if (context.Flags.DumpComputerStatus)
                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = ((NetApiStatus)taskResult).ToString(),
                            Task = "NetWkstaUserEnum"
                        });
                    return sessionList;
                }

                var iterator = ptrInfo;

                if (context.Flags.DumpComputerStatus)
                    OutputTasks.AddComputerStatus(new ComputerStatus
                    {
                        ComputerName = computer.DisplayName,
                        Status = "Success",
                        Task = "NetWkstaUserEnum"
                    });

                for (var i = 0; i < entriesRead; i++)
                {
                    var data = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(iterator, workstationInfoType);
                    iterator = (IntPtr)(iterator.ToInt64() + Marshal.SizeOf(workstationInfoType));

                    var domain = data.wkui1_logon_domain;
                    var username = data.wkui1_username;

                    //Remove local accounts
                    if (domain.Equals(computer.SamAccountName, StringComparison.CurrentCultureIgnoreCase))
                        continue;

                    //Remove blank accounts and computer accounts
                    if (username.Trim() == "" || username.EndsWith("$") || username == "ANONYMOUS LOGON" || username == context.CurrentUserName)
                        continue;

                    //Any domain with a space is unusable (ex: NT AUTHORITY, FONT DRIVER HOST)
                    if (domain.Contains(" "))
                        continue;

                    TypedPrincipal typedPrincipal = context.LDAPUtils.ResolveAccountName(username, domain).Result;
                    if (typedPrincipal == null)
                    {
                        sessionList.Add(new Session
                        {
                            UserId = typedPrincipal.ObjectIdentifier,
                            ComputerId = computer.ObjectIdentifier
                        });
                    }
                    else
                    {
                        sessionList.Add(new Session
                        {
                            UserId = $"{username}@{Helpers.NormalizeDomainName(domain)}".ToUpper(),
                            ComputerId = computer.ObjectIdentifier
                        });
                    }
                }

                return sessionList;
            }
            finally
            {
                if (ptrInfo != IntPtr.Zero)
                    NetApiBufferFree(ptrInfo);
            }
        }

        private static async Task<List<Session>> GetLoggedOnUsersRegistry(Context context, Computer computer)
        {
            var sessionList = new List<Session>();
            if (context.Flags.NoRegistryLoggedOn)
                return sessionList;

            RegistryKey key = null;
            try
            {
                //Try to open the remote base key
                var task = Task.Run(() => RegistryKey.OpenRemoteBaseKey(RegistryHive.Users, computer.APIName));
                if (await Task.WhenAny(task, Task.Delay(10000)) != task)
                {
                    if (context.Flags.DumpComputerStatus)
                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = "Timeout",
                            Task = "RegistryLoggedOn"
                        });

                    return sessionList;
                }

                key = task.Result;

                //Find subkeys where the regex matches
                var filteredKeys = key.GetSubKeyNames().Where(subkey => SidRegex.IsMatch(subkey));

                foreach (var sid in filteredKeys)
                {
                    sessionList.Add(new Session
                    {
                        ComputerId = computer.ObjectIdentifier,
                        UserId = sid
                    });
                }

                if (context.Flags.DumpComputerStatus)
                    OutputTasks.AddComputerStatus(new ComputerStatus
                    {
                        ComputerName = computer.DisplayName,
                        Status = "Success",
                        Task = "RegistryLoggedOn"
                    });
                return sessionList;
            }
            catch (Exception e)
            {
                if (context.Flags.DumpComputerStatus)
                    OutputTasks.AddComputerStatus(new ComputerStatus
                    {
                        ComputerName = computer.DisplayName,
                        Status = e.Message,
                        Task = "RegistryLoggedOn"
                    });
                return sessionList;
            }
            finally
            {
                //Ensure we dispose of the registry key
                key?.Dispose();
            }
        }

        #region NetWkstaGetInfo

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetWkstaUserEnum(
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(
            IntPtr Buff);

        #endregion
    }
}

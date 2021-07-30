using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHound.Tasks
{
    internal class NetSessionTasks
    {
        internal static async Task<LdapWrapper> ProcessNetSessions(Context context, LdapWrapper wrapper)
        {
            if (wrapper is Computer computer && computer.IsWindows && !computer.PingFailed)
            {
                //If ExcludeDC is set remove DCs from collection
                if (context.Flags.ExcludeDomainControllers && computer.IsDomainController)
                {
                    return wrapper;
                }

                //If stealth is set, only do session enum if the computer is marked as a stealth target
                if (context.Flags.Stealth && !computer.IsStealthTarget)
                    return wrapper;

                var sessions = await GetNetSessions(computer);
                var temp = computer.Sessions.ToList();
                temp.AddRange(sessions);
                computer.Sessions = temp.Distinct().ToArray();
                await DoDelay();
            }

            return wrapper;
        }

        /// <summary>
        /// Wraps the NetSessionEnum API call with a timeout and parses the results
        /// </summary>
        /// <param name="computer"></param>
        /// <returns></returns>
        private static async Task<List<Session>> GetNetSessions(Context context, Computer computer)
        {
            var resumeHandle = IntPtr.Zero;
            var sessionInfoType = typeof(SESSION_INFO_10);

            var entriesRead = 0;
            var ptrInfo = IntPtr.Zero;

            var sessionList = new List<Session>();

            try
            {
                var task = Task.Run(() => NetSessionEnum(computer.APIName, null, null, 10,
                    out ptrInfo, -1, out entriesRead, out _, ref resumeHandle));

                //10 second timeout
                if (await Task.WhenAny(task, Task.Delay(10000)) != task)
                {
                    if (context.Flags.DumpComputerStatus)
                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = "Timeout",
                            Task = "NetSessionEnum"
                        });
                    return sessionList;
                }

                var taskResult = task.Result;

                if (taskResult != 0)
                {
                    if (context.Flags.DumpComputerStatus)
                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = ((NetApiStatus)taskResult).ToString(),
                            Task = "NetSessionEnum"
                        });
                    return sessionList;
                }

                var sessions = new SESSION_INFO_10[entriesRead];
                var iterator = ptrInfo;

                for (var i = 0; i < entriesRead; i++)
                {
                    sessions[i] = (SESSION_INFO_10)Marshal.PtrToStructure(iterator, sessionInfoType);
                    iterator = (IntPtr)(iterator.ToInt64() + Marshal.SizeOf(sessionInfoType));
                }

                if (context.Flags.DumpComputerStatus)
                    OutputTasks.AddComputerStatus(new ComputerStatus
                    {
                        ComputerName = computer.DisplayName,
                        Status = "Success",
                        Task = "NetSessionEnum"
                    });

                foreach (var session in sessions)
                {
                    var sessionUsername = session.sesi10_username;
                    var computerName = session.sesi10_cname;

                    if (computerName == null)
                        continue;

                    string computerSid = null;

                    //Filter out computer accounts, Anonymous Logon, empty users
                    if (sessionUsername.EndsWith(
                        "$") || sessionUsername.Trim() == "" || sessionUsername == "$" || sessionUsername ==
                            context.CurrentUserName || sessionUsername == "ANONYMOUS LOGON")
                    {
                        continue;
                    }

                    //Remove leading backslashes
                    if (computerName.StartsWith("\\"))
                        computerName = computerName.TrimStart('\\');

                    //Remove empty sessions
                    if (string.IsNullOrEmpty(computerName))
                        continue;

                    //If the session is pointing to localhost, we already know what the SID of the computer is
                    if (computerName.Equals("[::1]") || computerName.Equals("127.0.0.1"))
                        computerSid = computer.ObjectIdentifier;

                    //Try converting the computer name to a SID if we didn't already get it from a localhost
                    computerSid = computerSid ?? context.LDAPUtils.ResolveHostToSid(computerName, computer.Domain);

                    //Try converting the username to a SID
                    var searcher = Helpers.GetDirectorySearcher(computer.Domain);
                    var sids = await searcher.LookupUserInGC(sessionUsername);
                    if (sids?.Length > 0)
                    {
                        foreach (var sid in sids)
                        {
                            sessionList.Add(new Session
                            {
                                ComputerId = computerSid,
                                UserId = sid
                            });
                        }
                    }
                    else
                    {
                        TypedPrincipal typedPrincipal = context.LDAPUtils.ResolveAccountName(sessionUsername, computer.Domain);
                        if (typedPrincipal == null)
                        {
                            sessionList.Add(new Session
                            {
                                ComputerId = computerSid,
                                UserId = sid
                            });
                        }
                        else
                        {
                            sessionList.Add(new Session
                            {
                                ComputerId = computerSid,
                                UserId = sessionUsername
                            });
                        }
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

        #region NetSessionEnum Imports

        [DllImport("NetAPI32.dll", SetLastError = true)]
        private static extern int NetSessionEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
            [MarshalAs(UnmanagedType.LPWStr)] string UserName,
            int Level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref IntPtr resume_handle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SESSION_INFO_10
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi10_cname;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi10_username;
            public uint sesi10_time;
            public uint sesi10_idle_time;
        }

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(
            IntPtr Buff);
        #endregion
    }
}

using System;
using System.Threading.Tasks;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;

namespace SharpHound.Tasks
{
    /// <summary>
    /// Tasks to check if we should do further API calls to computers
    /// </summary>
    internal class ComputerAvailableTasks
    {
        internal static async Task<LdapWrapper> CheckSMBOpen(Context context, LdapWrapper wrapper)
        {
            //Only perform checks if this is a Computer object
            if (wrapper is Computer computer)
            {
                //Stealth targetting - we've already determined our stealth targets, so if its not a stealth target, return
                if (context.Flags.Stealth && !computer.IsStealthTarget)
                    return wrapper;

                if (context.Flags.WindowsOnly)
                {
                    //If the WindowsOnly flag is set, check the operatingsystem attribute
                    var os = wrapper.SearchResult.GetProperty("operatingsystem");

                    //Perform a search for the term windows in the operatingsystem string
                    if (!(os?.IndexOf("windows", StringComparison.CurrentCultureIgnoreCase) > -1))
                    {
                        //If this isn't a windows computer, we'll mark is as such and we'll skip the following port scan since its not necessary
                        computer.IsWindows = false;

                        //Add a computer status message to note why we skipped this computer
                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = "NotWindows",
                            Task = "SMBCheck"
                        });
                        return wrapper;
                    }
                }

                //If we're skipping port scan, just return the wrapper. PingFailed is set to false by default
                if (context.Flags.SkipPortScan)
                    return wrapper;

                //Do a check on port 445 and save the result
                computer.PingFailed = Helpers.CheckPort(computer.APIName, 445) == false;
                if (computer.PingFailed && context.Flags.DumpComputerStatus)
                {
                    //If the port check failed, add a computer status note
                    OutputTasks.AddComputerStatus(new ComputerStatus
                    {
                        ComputerName = computer.DisplayName,
                        Status = "SMBNotAvailable",
                        Task = "SMBCheck"
                    });
                }

                //Do jitter/delay if specified
                await Helpers.DoDelay();
            }

            return wrapper;
        }
    }
}

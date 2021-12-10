using System;
using System.IO;
using Microsoft.Win32;
using Sharphound.Client;
using SharpHoundCommonLib;

namespace Sharphound.Runtime
{
    public class ClientHelpers
    {
        private static readonly string ProcStartTime = $"{DateTime.Now:yyyyMMddHHmmss}";

        /// <summary>
        ///     Creates a filename for the looped results which will contain the results of all loops
        /// </summary>
        /// <returns></returns>
        internal static string GetLoopFileName(IContext context)
        {
            var finalFilename =
                context.ZipFilename == null ? "BloodHoundLoopResults.zip" : $"{context.ZipFilename}.zip";

            if (context.Flags.RandomizeFilenames) finalFilename = $"{Path.GetRandomFileName()}.zip";

            finalFilename = $"{ProcStartTime}_{finalFilename}";

            if (context.OutputPrefix != null) finalFilename = $"{context.OutputPrefix}_{finalFilename}";

            var finalPath = Path.Combine(context.OutputDirectory, finalFilename);

            return finalPath;
        }

        internal static string GetBase64MachineID()
        {
            try
            {
                //Force opening the registry key as the Registry64 view
                using (var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                {
                    var crypto = key.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false);
                    //Default to the machine name if something fails for some reason
                    if (crypto == null) return $"{Helpers.Base64(Environment.MachineName)}";

                    var guid = crypto.GetValue("MachineGuid") as string;
                    return Helpers.Base64(guid);
                }
            }
            catch
            {
                return $"{Helpers.Base64(Environment.MachineName)}";
            }
        }
    }
}
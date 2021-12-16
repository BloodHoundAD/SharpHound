using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using Sharphound.Runtime;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Timer = System.Timers.Timer;

namespace Sharphound
{
    /// <summary>
    ///     Console Context holds the various properties to be populated/validated by the chain of responsibility.
    /// </summary>
    public sealed class BaseContext : IDisposable, IContext
    {
        private static readonly string CurrentLoopTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        private static readonly Lazy<Random> RandomGen = new();

        private bool disposedValue;

        public BaseContext(ILogger logger, LDAPConfig ldapConfig, Flags flags)
        {
            Logger = logger;
            Flags = flags;
            LDAPUtils = new LDAPUtils();
            LDAPUtils.SetLDAPConfig(ldapConfig);
            CancellationTokenSource = new CancellationTokenSource();
        }

        public bool IsFaulted { get; set; }

        public ResolvedCollectionMethod ResolvedCollectionMethods { get; set; }
        public string LdapFilter { get; set; }
        public string SearchBase { get; set; }
        public string DomainName { get; set; }
        public string CacheFileName { get; set; }
        public string ComputerFile { get; set; }
        public string ZipFilename { get; set; }
        public string ZipPassword { get; set; }
        public string CurrentUserName { get; set; }
        public ILogger Logger { get; set; }
        public Timer Timer { get; set; }
        public DateTime LoopEnd { get; set; }
        public TimeSpan LoopDuration { get; set; }
        public TimeSpan LoopInterval { get; set; }
        public int StatusInterval { get; set; }
        public int Threads { get; set; }
        public string RealDNSName { get; set; }
        public string OutputPrefix { get; set; }
        public string OutputDirectory { get; set; }
        public int Throttle { get; set; }
        public int Jitter { get; set; }
        public int PortScanTimeout { get; set; } = 500;
        public CancellationTokenSource CancellationTokenSource { get; set; }
        public ILDAPUtils LDAPUtils { get; set; }
        public Task CollectionTask { get; set; }
        public Flags Flags { get; set; }

        public async Task DoDelay()
        {
            if (Throttle == 0)
                return;

            if (Jitter == 0)
            {
                await Task.Delay(Throttle);
                return;
            }

            var percent = (int)Math.Floor((double)(Jitter * (Throttle / 100)));
            var delay = Throttle + RandomGen.Value.Next(-percent, percent);
            await Task.Delay(delay);
        }

        public string GetCachePath()
        {
            var cacheFileName = CacheFileName ?? $"{ClientHelpers.GetBase64MachineID()}.bin";
            var path = Path.Combine(OutputDirectory, cacheFileName);
            return path;
        }

        public ResolvedCollectionMethod SetupMethodsForLoop()
        {
            var original = ResolvedCollectionMethods;
            const ResolvedCollectionMethod computerCollectionMethods =
                ResolvedCollectionMethod.LocalGroups | ResolvedCollectionMethod.LoggedOn |
                ResolvedCollectionMethod.Session;
            return original & computerCollectionMethods;
        }

        public string ResolveFileName(string filename, string extension, bool addTimestamp)
        {
            var finalFilename = filename;
            if (!filename.EndsWith(extension))
                finalFilename = $"{filename}.{extension}";

            if (extension is "json" or "zip" && Flags.RandomizeFilenames)
                finalFilename = $"{Path.GetRandomFileName()}";

            if (addTimestamp) finalFilename = $"{CurrentLoopTime}_{finalFilename}";

            if (OutputPrefix != null) finalFilename = $"{OutputPrefix}_{finalFilename}";

            var finalPath = Path.Combine(OutputDirectory, finalFilename);

            return finalPath;
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~Context()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        /// <summary>
        ///     TODO: Implement the primary dispose pattern
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        ///     TODO: Implement the primary dispose pattern
        /// </summary>
        /// <param name="disposing"></param>
        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }
    }
}
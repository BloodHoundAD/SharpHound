using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ICSharpCode.SharpZipLib.Core;
using ICSharpCode.SharpZipLib.Zip;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using SharpHoundCommonLib.Enums;

namespace Sharphound.Runtime
{
    public class LoopManager
    {
        private readonly IContext _context;
        private readonly ResolvedCollectionMethod _methods;
        private int _loopCount = 0;
        private readonly DateTime _loopEndTime;
        private readonly List<string> _filenames;

        public LoopManager(IContext context)
        {
            _context = context;
            _methods = _context.ResolvedCollectionMethods.GetLoopCollectionMethods();
            _loopEndTime = DateTime.Now.Add(_context.LoopDuration);
            _filenames = new List<string>();
        }

        public async Task StartLooping()
        {
            if (!_context.Flags.Loop)
                return;

            if (_context.CancellationTokenSource.IsCancellationRequested)
            {
                _context.Logger.LogInformation("Skipping loop because cancellation was requested");
                return;
            }
            
            _context.Logger.LogInformation("Waiting 30 seconds before starting loop");
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), _context.CancellationTokenSource.Token);
            }
            catch (TaskCanceledException)
            {
                _context.Logger.LogInformation("Skipping loop because cancellation was requested");
            }

            while (!_context.CancellationTokenSource.IsCancellationRequested)
            {
                _loopCount++;
                var time = DateTime.Now;
                if (time >= _loopEndTime)
                {
                    break;
                }
                
                _context.Logger.LogInformation("Starting loop {LoopCount} at {Time} on {Date}", _loopCount, time.ToShortTimeString(), time.ToShortDateString());
                var task = new CollectionTask(_context).StartCollection();

                var filename = await task;
                _filenames.Add(filename);

                try
                {
                    await Task.Delay(_context.LoopInterval, _context.CancellationTokenSource.Token);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
            }
            
            var zipName = ZipFiles();
            _context.Logger.LogInformation("SharpHound completed {Number} loops! Zip file written to {Filename} ", _loopCount, zipName);
        }

        private string ZipFiles()
        {
            if (_context.Flags.NoOutput || _context.Flags.NoZip)
                return null;

            var baseFilename = _context.ZipFilename ?? "BloodHoundLoopResults";
            var resolvedFileName = _context.ResolveFileName(baseFilename, "zip", true);
            
            if (File.Exists(resolvedFileName))
                resolvedFileName = _context.ResolveFileName(Path.GetRandomFileName(), "zip", true);

            using var fs = File.Create(resolvedFileName);
            using var zipStream = new ZipOutputStream(fs);
            zipStream.SetLevel(9);

            if (_context.ZipPassword != null) zipStream.Password = _context.ZipPassword;

            foreach (var entry in _filenames.Where(x => !string.IsNullOrEmpty(x)))
            {
                var fi = new FileInfo(entry);
                var zipEntry = new ZipEntry(fi.Name) { DateTime = fi.LastWriteTime, Size = fi.Length };
                zipStream.PutNextEntry(zipEntry);

                var buffer = new byte[4096];
                using (var fileStream = File.OpenRead(entry))
                {
                    StreamUtils.Copy(fileStream, zipStream, buffer);
                }

                zipStream.CloseEntry();

                File.Delete(entry);
            }

            return resolvedFileName;
        }
    }
}
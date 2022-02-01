using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Timers;
using ICSharpCode.SharpZipLib.Core;
using ICSharpCode.SharpZipLib.Zip;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using Sharphound.Writers;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace Sharphound.Runtime
{
    public class OutputWriter
    {
        private readonly JsonDataWriter<Computer> _computerOutput;
        private readonly JsonDataWriter<Container> _containerOutput;
        private readonly IContext _context;
        private readonly JsonDataWriter<Domain> _domainOutput;
        private readonly JsonDataWriter<GPO> _gpoOutput;
        private readonly JsonDataWriter<Group> _groupOutput;
        private readonly JsonDataWriter<OU> _ouOutput;
        private readonly Channel<OutputBase> _outputChannel;
        private readonly Timer _statusTimer;
        private readonly JsonDataWriter<User> _userOutput;

        private int _completedCount;
        private int _lastCount;
        private Stopwatch _runTimer;

        public OutputWriter(IContext context, Channel<OutputBase> outputChannel)
        {
            _context = context;
            _outputChannel = outputChannel;
            _userOutput = new JsonDataWriter<User>(_context, DataType.Users);
            _computerOutput = new JsonDataWriter<Computer>(_context, DataType.Computers);
            _domainOutput = new JsonDataWriter<Domain>(_context, DataType.Domains);
            _groupOutput = new JsonDataWriter<Group>(_context, DataType.Groups);
            _gpoOutput = new JsonDataWriter<GPO>(_context, DataType.GPOs);
            _ouOutput = new JsonDataWriter<OU>(_context, DataType.OUs);
            _containerOutput = new JsonDataWriter<Container>(_context, DataType.Containers);

            _runTimer = new Stopwatch();
            _statusTimer = new Timer(_context.StatusInterval);
            _statusTimer.Elapsed += (_, _) =>
            {
                PrintStatus();
                _lastCount = _completedCount;
            };
            _statusTimer.AutoReset = true;
        }

        internal void StartStatusOutput()
        {
            _runTimer = Stopwatch.StartNew();
            _statusTimer.Start();
        }

        private void CloseOutput()
        {
            PrintStatus();
            _context.Logger.LogInformation("Enumeration finished in {RunTime}", _runTimer.Elapsed);
        }

        private void PrintStatus()
        {
            var log = _context.Logger;
            if (_runTimer != null)
                log.LogInformation(
                    "Status: {Completed} objects finished (+{ElapsedObjects} {ObjectsPerSecond})/s -- Using {RAM} MB RAM",
                    _completedCount, _completedCount - _lastCount,
                    (float)_completedCount / (_runTimer.ElapsedMilliseconds / 1000),
                    Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024);
            else
                log.LogInformation("Status: {Completed} objects finished (+{ElapsedObjects}) -- Using {RAM} MB RAM",
                    _completedCount, _completedCount - _lastCount,
                    Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024);
        }

        internal async Task<string> StartWriter()
        {
            while (await _outputChannel.Reader.WaitToReadAsync())
            {
                if (!_outputChannel.Reader.TryRead(out var item)) continue;
                _completedCount++;
                switch (item)
                {
                    case Computer computer:
                        await _computerOutput.AcceptObject(computer);
                        break;
                    case Container container:
                        await _containerOutput.AcceptObject(container);
                        break;
                    case Domain domain:
                        await _domainOutput.AcceptObject(domain);
                        break;
                    case GPO gpo:
                        await _gpoOutput.AcceptObject(gpo);
                        break;
                    case Group group:
                        await _groupOutput.AcceptObject(group);
                        break;
                    case OU ou:
                        await _ouOutput.AcceptObject(ou);
                        break;
                    case User user:
                        await _userOutput.AcceptObject(user);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(item));
                }
            }

            Console.WriteLine("Closing writers");
            return await FlushWriters();
        }

        private async Task<string> FlushWriters()
        {
            await _computerOutput.FlushWriter();
            await _userOutput.FlushWriter();
            await _groupOutput.FlushWriter();
            await _domainOutput.FlushWriter();
            await _gpoOutput.FlushWriter();
            await _ouOutput.FlushWriter();
            await _containerOutput.FlushWriter();
            CloseOutput();
            var fileName = ZipFiles();
            return fileName;
        }

        private string ZipFiles()
        {
            if (_context.Flags.NoZip || _context.Flags.NoOutput)
                return null;

            var filename = string.IsNullOrEmpty(_context.ZipFilename) ? "BloodHound" : _context.ZipFilename;
            var resolvedFileName = _context.ResolveFileName(filename, "zip", true);

            if (File.Exists(resolvedFileName))
                resolvedFileName = _context.ResolveFileName(Path.GetRandomFileName(), "zip", true);

            using var fs = File.Create(resolvedFileName);
            using var zipStream = new ZipOutputStream(fs);
            zipStream.SetLevel(9);

            if (_context.ZipPassword != null) zipStream.Password = _context.ZipPassword;

            var fileList = new List<string>();
            fileList.AddRange(new[]
            {
                _computerOutput.GetFilename(), _userOutput.GetFilename(), _groupOutput.GetFilename(),
                _containerOutput.GetFilename(), _domainOutput.GetFilename(), _gpoOutput.GetFilename(),
                _ouOutput.GetFilename()
            });

            foreach (var entry in fileList.Where(x => !string.IsNullOrEmpty(x)))
            {
                var fi = new FileInfo(entry);
                var zipEntry = new ZipEntry(fi.Name) { DateTime = fi.LastWriteTime, Size = fi.Length };
                zipStream.PutNextEntry(zipEntry);

                var buffer = new byte[4096];
                using (var fileStream = File.OpenRead(entry))
                {
                    StreamUtils.Copy(fileStream, zipStream, buffer);
                }

                try
                {
                    zipStream.CloseEntry();
                    File.Delete(entry);
                }
                catch (Exception e)
                {
                    _context.Logger.LogError(e, "Error adding {Filename} to the zip", entry);
                }
            }

            return resolvedFileName;
        }
    }
}
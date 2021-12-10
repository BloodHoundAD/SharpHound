using System;
using System.IO;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;
using SharpHound.Core.Behavior;
using SharpHoundCommonLib;

namespace SharpHound.Writers
{
    internal class CompStatusWriter : BaseWriter<CSVComputerStatus>
    {
        private static readonly object LockObj = new();
        private readonly Channel<CSVComputerStatus> _channel;
        private readonly Context _context;
        private StreamWriter _streamWriter;

        public CompStatusWriter(Context context, Channel<CSVComputerStatus> channel) : base("compstatus")
        {
            _context = context;
            _channel = channel;
            _channel = channel;
            if (!_context.Flags.DumpComputerStatus)
            {
                _noOp = true;
            }
        }

        protected override async Task WriteData()
        {
            foreach (var item in Queue) await _streamWriter.WriteLineAsync(item.ToCsv());
        }

        internal async Task StartWriter()
        {
            if (_context.Flags.DumpComputerStatus)
            {
                while (await _channel.Reader.WaitToReadAsync())
                {
                    if (!_channel.Reader.TryRead(out var item)) continue;
                    await AcceptObject(item);
                }

                await FlushWriter();
            }
        }

        internal override async Task FlushWriter()
        {
            await WriteData();
            await _streamWriter.FlushAsync();
        }

        protected override void CreateFile()
        {
            var filename = _context.ResolveFileName(DataType, "csv", true);
            var exists = File.Exists(filename);
            _streamWriter = new StreamWriter(
                new FileStream(filename, exists ? FileMode.Truncate : FileMode.Create, FileAccess.ReadWrite),
                Encoding.UTF8);
            _streamWriter.WriteLine("ComputerName,Task,Status");
        }

        internal void CloseLog()
        {
            try
            {
                lock (LockObj)
                {
                    _streamWriter.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error closing task log: {e}");
            }
        }
    }
}
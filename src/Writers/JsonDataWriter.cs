using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Sharphound.Client;
using SharpHoundCommonLib.OutputTypes;
using Utf8Json;

namespace Sharphound.Writers
{
    /// <summary>
    ///     An implementation of BaseWriter which writes data directly to JSON
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class JsonDataWriter<T> : BaseWriter<T>
    {
        private const string FileStart = @"{""data"":[";
        private const string FileStartPretty = "{\n\t\"data\":[\n";
        private readonly IContext _context;
        private string _fileName;
        private bool _initialWrite = true;
        private StreamWriter _streamWriter;

        /// <summary>
        ///     Creates a new instance of a JSONWriter using the specified datatype and program context
        /// </summary>
        /// <param name="context"></param>
        /// <param name="dataType"></param>
        public JsonDataWriter(IContext context, string dataType) : base(dataType)
        {
            _context = context;
            if (_context.Flags.NoOutput)
                NoOp = true;
        }

        /// <summary>
        ///     Opens a new file handle for writing. Throws an exception if the file already exists.
        /// </summary>
        /// <exception cref="FileExistsException"></exception>
        protected override void CreateFile()
        {
            var filename = _context.ResolveFileName(DataType, "json", true);
            if (File.Exists(filename))
                throw new FileExistsException($"File {filename} already exists. This should never happen!");

            _fileName = filename;

            _streamWriter = new StreamWriter(filename, false, Encoding.UTF8);
            _streamWriter.Write(_context.Flags.PrettyPrint ? FileStartPretty : FileStart);
        }

        /// <summary>
        ///     Flushes data to the file by serializing to JSON and then writing with appropriate seperators
        /// </summary>
        protected override async Task WriteData()
        {
            if (!_initialWrite)
                await _streamWriter.WriteAsync(",");
            else
                _initialWrite = false;

            if (_context.Flags.PrettyPrint)
            {
                await _streamWriter.WriteAsync(string.Join(",",Queue.Select(x => JsonSerializer.PrettyPrint(JsonSerializer.Serialize(x), 2))));
            }
            else
            {
                await _streamWriter.WriteAsync(string.Join(",", Queue.Select(JsonSerializer.ToJsonString)));    
            }
            
            Queue.Clear();
        }

        /// <summary>
        ///     Flushes remaining data to the file and then manually writes JSON tags to close the file out
        /// </summary>
        internal override async Task FlushWriter()
        {
            if (!FileCreated)
                return;
            
            if (Queue.Count > 0)
            {
                if (!_initialWrite)
                {
                    await _streamWriter.WriteAsync(",");
                }
                
                if (_context.Flags.PrettyPrint)
                {
                    await _streamWriter.WriteAsync(string.Join(",",Queue.Select(x => JsonSerializer.PrettyPrint(JsonSerializer.ToJsonString(x)))));
                }
                else
                {
                    await _streamWriter.WriteAsync(string.Join(",", Queue.Select(JsonSerializer.ToJsonString)));    
                }
                Queue.Clear();
            }
            

            if (_context.Flags.PrettyPrint)
            {
                await _streamWriter.WriteAsync("],\n\"meta\":");    
            }
            else
            {
                await _streamWriter.WriteAsync(@"],""meta"":");    
            }
            
            var meta = new MetaTag
            {
                Count = Count,
                CollectionMethods = (long)_context.ResolvedCollectionMethods,
                DataType = DataType,
                Version = 4
            };
            
            if (_context.Flags.PrettyPrint)
            {
                await _streamWriter.WriteAsync(JsonSerializer.PrettyPrint(JsonSerializer.ToJsonString(meta)));
                await _streamWriter.WriteAsync("\n}");
            }
            else
            {
                await _streamWriter.WriteAsync(JsonSerializer.ToJsonString(meta));
                await _streamWriter.WriteAsync("}");
            }
            
            await _streamWriter.FlushAsync();
            _streamWriter.Close();
        }

        /// <summary>
        ///     Get the file name used by this writer
        /// </summary>
        /// <returns></returns>
        internal string GetFilename()
        {
            return FileCreated ? _fileName : null;
        }
    }
}
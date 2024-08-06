﻿using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using Sharphound.Client;
using SharpHoundCommonLib.OutputTypes;

namespace Sharphound.Writers
{
    /// <summary>
    ///     An implementation of BaseWriter which writes data directly to JSON
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class JsonDataWriter<T> : BaseWriter<T>
    {
        private JsonTextWriter _jsonWriter;
        private readonly IContext _context;
        private string _fileName;
        private JsonSerializerSettings _serializerSettings;

        private const int DataVersion = 6;

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

            _serializerSettings = new JsonSerializerSettings()
            {
                Converters = new List<JsonConverter>
                {
                    new StringEnumConverter()
                },
                Formatting = PrettyPrint
            };
        }

        private Formatting PrettyPrint => _context.Flags.PrettyPrint ? Formatting.Indented : Formatting.None;

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

            _jsonWriter = new JsonTextWriter(new StreamWriter(filename, false, new UTF8Encoding(false)));
            _jsonWriter.Formatting = PrettyPrint;
            _jsonWriter.WriteStartObject();
            _jsonWriter.WritePropertyName("data");
            _jsonWriter.WriteStartArray();
        }

        /// <summary>
        ///     Flushes data to the file by serializing to JSON and then writing with appropriate seperators
        /// </summary>
        protected override async Task WriteData()
        {
            foreach (var item in Queue)
            {
                await _jsonWriter.WriteRawValueAsync(JsonConvert.SerializeObject(item, _serializerSettings));
            }
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
                await WriteData();
            }
            
            var meta = new MetaTag
            {
                Count = Count,
                CollectionMethods = (long)_context.ResolvedCollectionMethods,
                DataType = DataType,
                Version = DataVersion,
                CollectorVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString()
            };
            
            await _jsonWriter.FlushAsync();
            await _jsonWriter.WriteEndArrayAsync();
            await _jsonWriter.WritePropertyNameAsync("meta");
            await _jsonWriter.WriteRawValueAsync(JsonConvert.SerializeObject(meta, PrettyPrint));
            await _jsonWriter.FlushAsync();
            await _jsonWriter.CloseAsync();
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
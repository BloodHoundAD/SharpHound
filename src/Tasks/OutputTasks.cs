using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Timers;
using ICSharpCode.SharpZipLib.Zip;
using Newtonsoft.Json;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHound.Producers;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using Group = SharpHound.LdapWrappers.Group;

namespace SharpHound.Tasks
{
    internal class OutputTasks
    {
        private static readonly List<string> UsedFileNames = new List<string>();
        private static readonly List<string> ZipFileNames = new List<string>();
        private static Lazy<JsonFileWriter> _userOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("users"), false);
        private static Lazy<JsonFileWriter> _groupOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("groups"), false);
        private static Lazy<JsonFileWriter> _computerOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("computers"), false);
        private static Lazy<JsonFileWriter> _domainOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("domains"), false);
        private static Lazy<JsonFileWriter> _gpoOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("gpos"), false);
        private static Lazy<JsonFileWriter> _ouOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("ous"), false);
        private static int _lastCount;
        private static int _currentCount;
        private static Timer _statusTimer;
        private static Stopwatch _runTimer;
        private static Task _computerStatusTask;
        private static readonly ConcurrentDictionary<string, int> ComputerStatusCount = new ConcurrentDictionary<string, int>();
        private static readonly BlockingCollection<ComputerStatus> ComputerStatusQueue = new BlockingCollection<ComputerStatus>();
        internal static readonly Lazy<string> ZipPasswords = new Lazy<string>(GenerateZipPassword);
        internal static ConcurrentDictionary<string, string> SeenCommonPrincipals = new ConcurrentDictionary<string, string>();

        internal static void StartOutputTimer(double statusInterval)
        {
            PrintStatus();
            _statusTimer = new Timer(statusInterval);
            _runTimer = new Stopwatch();
            _runTimer.Start();
            _statusTimer.Elapsed += (sender, e) =>
            {
                PrintStatus();
                _lastCount = _currentCount;
            };
            _statusTimer.AutoReset = true;
            _statusTimer.Start();
        }

        internal static void PrintStatus()
        {
            Console.WriteLine(
                _runTimer != null
                    ? $"Status: {_currentCount} objects finished (+{_currentCount - _lastCount} {(float)_currentCount / (_runTimer.ElapsedMilliseconds / 1000)})/s -- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024} MB RAM"
                    : $"Status: {_currentCount} objects finished (+{_currentCount - _lastCount}) -- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024} MB RAM");
        }

        internal static void WriteJsonOutput(LdapWrapper wrapper)
        {
            switch (wrapper)
            {
                case Computer computer:
                    _computerOutput.Value.WriteObject(computer);
                    break;
                case Domain domain:
                    _domainOutput.Value.WriteObject(domain);
                    break;
                case GPO gpo:
                    _gpoOutput.Value.WriteObject(gpo);
                    break;
                case Group group:
                    _groupOutput.Value.WriteObject(group);
                    break;
                case OU ou:
                    _ouOutput.Value.WriteObject(ou);
                    break;
                case User user:
                    _userOutput.Value.WriteObject(user);
                    break;
            }

            _currentCount++;
        }

        internal static async Task CompleteOutput(Context context)
        {
            PrintStatus();
            Console.WriteLine($"Enumeration finished in {_runTimer.Elapsed}");

            if (context.Flags.DumpComputerStatus)
            {
                CompleteComputerStatusOutput();
                await _computerStatusTask;
            }

            var domainName = context.(context.DomainName);
            var forestName = context.LDAPUtils.GetForest(domainName).Name;
            var dcSids = BaseProducer.GetDomainControllers();
            var domainSid = new SecurityIdentifier(dcSids.First().Key).AccountDomainSid.Value.ToUpper();
            var enterpriseDomainControllers = new Group(null)
            {
                ObjectIdentifier = $"{forestName}-S-1-5-9",
                Domain = forestName,
                Members = BaseProducer.GetDomainControllers().Keys.Select(sid => new GenericMember
                {
                    MemberId = sid,
                    MemberType = Label.Computer
                }).ToArray()
            };

            enterpriseDomainControllers.Properties.Add("name", $"ENTERPRISE DOMAIN CONTROLLERS@{forestName}");
            enterpriseDomainControllers.Properties.Add("domain", forestName);

            _groupOutput.Value.WriteObject(enterpriseDomainControllers);

            var members = new[]
            {
                new GenericMember
                {
                    MemberType = Label.Group,
                    MemberId = $"{domainSid}-515"
                },
                new GenericMember
                {
                    MemberType = Label.Group,
                    MemberId = $"{domainSid}-513"
                }
            };

            var everyone = new Group(null)
            {
                ObjectIdentifier = $"{domainName}-S-1-1-0",
                Domain = domainName,
                Members = members
            };

            everyone.Properties.Add("name", $"EVERYONE@{domainName}");
            everyone.Properties.Add("domain", domainName);

            _groupOutput.Value.WriteObject(everyone);

            var authUsers = new Group(null)
            {
                ObjectIdentifier = $"{domainName}-S-1-5-11",
                Domain = domainName,
                Members = members
            };

            authUsers.Properties.Add("name", $"AUTHENTICATED USERS@{domainName}");
            authUsers.Properties.Add("domain", domainName);

            _groupOutput.Value.WriteObject(authUsers);

            //Write objects for common principals
            foreach (var seen in SeenCommonPrincipals)
            {
                var domain = seen.Key;
                var sid = seen.Value;

                WellKnownPrincipal.GetWellKnownPrincipal(sid, out var principal);

                sid = context.LDAPUtils.ConvertWellKnownPrincipal(sid, domain);
                switch (principal.ObjectType)
                {
                    case Label.User:
                        var u = new User(null)
                        {
                            ObjectIdentifier = sid
                        };
                        u.Properties.Add("name", $"{principal.ObjectIdentifier}@{domain}".ToUpper());
                        u.Properties.Add("domain", domain);
                        _userOutput.Value.WriteObject(u);
                        break;
                    case Label.Computer:
                        var c = new Computer(null)
                        {
                            ObjectIdentifier = sid
                        };

                        c.Properties.Add("name", $"{principal.ObjectIdentifier}@{domain}".ToUpper());
                        c.Properties.Add("domain", domain);
                        _computerOutput.Value.WriteObject(c);
                        break;
                    case Label.Group:
                        var g = new Group(null)
                        {
                            ObjectIdentifier = sid
                        };
                        g.Properties.Add("name", $"{principal.ObjectIdentifier}@{domain}".ToUpper());
                        g.Properties.Add("domain", domain);
                        _groupOutput.Value.WriteObject(g);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }

            _runTimer.Stop();
            _statusTimer.Stop();
            if (_userOutput.IsValueCreated)
                _userOutput.Value.CloseWriter();
            if (_computerOutput.IsValueCreated)
                _computerOutput.Value.CloseWriter();
            if (_groupOutput.IsValueCreated)
                _groupOutput.Value.CloseWriter();
            if (_domainOutput.IsValueCreated)
                _domainOutput.Value.CloseWriter();
            if (_gpoOutput.IsValueCreated)
                _gpoOutput.Value.CloseWriter();
            if (_ouOutput.IsValueCreated)
                _ouOutput.Value.CloseWriter();

            _userOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("users"), false);
            _groupOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("groups"), false);
            _computerOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("computers"), false);
            _domainOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("domains"), false);
            _gpoOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("gpos"), false);
            _ouOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter("ous"), false);

            string finalName;
            
            if (context.Flags.NoZip || context.Flags.NoOutput)
                return;

            if (context.ZipFilename != null)
                finalName = context.ResolveFileName(context, context.ZipFilename, "zip", true);
            else
            {
                finalName = context.ResolveFileName(context, "BloodHound", "zip", true);
            }

            Console.WriteLine($"Compressing data to {finalName}");

            var buffer = new byte[4096];

            if (File.Exists(finalName))
            {
                Console.WriteLine("Zip File already exists, randomizing filename");
                finalName = context.ResolveFileName(context, Path.GetRandomFileName(), "zip", true);
                Console.WriteLine($"New filename is {finalName}");
            }

            using (var zipStream = new ZipOutputStream(File.Create(finalName)))
            {
                //Set level to 9, maximum compressions
                zipStream.SetLevel(9);

                if (context.Flags.EncryptZip)
                {
                    if (!context.Flags.Loop)
                    {
                        var password = ZipPasswords.Value;
                        zipStream.Password = password;

                        Console.WriteLine($"Password for Zip file is {password}. Unzip files manually to upload to interface");
                    }
                }
                else
                {
                    Console.WriteLine("You can upload this file directly to the UI");
                }

                foreach (var file in UsedFileNames)
                {
                    var entry = new ZipEntry(Path.GetFileName(file)) { DateTime = DateTime.Now };
                    zipStream.PutNextEntry(entry);

                    using (var fileStream = File.OpenRead(file))
                    {
                        int source;
                        do
                        {
                            source = await fileStream.ReadAsync(buffer, 0, buffer.Length);
                            zipStream.Write(buffer, 0, source);
                        } while (source > 0);
                    }

                    File.Delete(file);
                }

                zipStream.Finish();
            }

            if (context.Flags.Loop)
                ZipFileNames.Add(finalName);

            UsedFileNames.Clear();
        }

        internal static async Task CollapseLoopZipFiles(Context context)
        {
            if (context.Flags.NoOutput || context.Flags.NoZip)
                return;

            var finalName = Helpers.GetLoopFileName();

            Console.WriteLine($"Compressing zip files to {finalName}");

            var buffer = new byte[4096];

            if (File.Exists(finalName))
            {
                Console.WriteLine("Zip File already exists, randomizing filename");
                finalName = context.ResolveFileName(context, Path.GetRandomFileName(), "zip", true);
                Console.WriteLine($"New filename is {finalName}");
            }

            using (var zipStream = new ZipOutputStream(File.Create(finalName)))
            {
                //Set level to 0, since we're just storing the other zips
                zipStream.SetLevel(0);

                if (context.Flags.EncryptZip)
                {
                    var password = ZipPasswords.Value;
                    zipStream.Password = password;
                    Console.WriteLine($"Password for zip file is {password}. Unzip files manually to upload to interface");
                }
                else
                {
                    Console.WriteLine("Unzip the zip file and upload the other zips to the interface");
                }

                foreach (var file in ZipFileNames)
                {
                    var entry = new ZipEntry(Path.GetFileName(file)) { DateTime = DateTime.Now };
                    zipStream.PutNextEntry(entry);

                    using (var fileStream = File.OpenRead(file))
                    {
                        int source;
                        do
                        {
                            source = await fileStream.ReadAsync(buffer, 0, buffer.Length);
                            zipStream.Write(buffer, 0, source);
                        } while (source > 0);
                    }

                    File.Delete(file);
                }

                zipStream.Finish();
            }
        }

        private static string GenerateZipPassword(Context context)
        {
            const string space = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            var builder = new StringBuilder();
            var random = new Random();
            for (var i = 0; i < 10; i++)
            {
                builder.Append(space[random.Next(space.Length)]);
            }
            return builder.ToString();
        }

        internal static void StartComputerStatusTask(Context context)
        {
            if (!context.Flags.DumpComputerStatus)
            {
                _computerStatusTask = null;
                return;
            }

            _computerStatusTask = Task.Factory.StartNew(() =>
            {
                var fileName = context.ResolveFileName(context, "computerstatus", "csv", true);
                UsedFileNames.Add(fileName);
                var count = 0;
                using (var writer = new StreamWriter(fileName, false))
                {
                    writer.WriteLine("ComputerName, Task, Status");
                    foreach (var error in ComputerStatusQueue.GetConsumingEnumerable())
                    {
                        writer.WriteLine(error.ToCsv());
                        count++;
                        if (count % 100 == 0)
                            writer.Flush();
                    }

                    writer.Flush();
                }
            }, TaskCreationOptions.LongRunning);
        }

        internal static void AddComputerStatus(ComputerStatus status)
        {
            ComputerStatusQueue.Add(status);
            var hash = $"{status.Task}-{Regex.Replace(status.Status, @"\t|\n|\r", "")}";
            ComputerStatusCount.AddOrUpdate(hash, 1, (id, count) => count + 1);
        }

        private static void CompleteComputerStatusOutput()
        {
            ComputerStatusQueue.CompleteAdding();
            Console.WriteLine();
            Console.WriteLine("-------Computer Status Count-------");
            foreach (var key in ComputerStatusCount)
            {
                Console.WriteLine($"{key.Key}: {key.Value}");
            }
            Console.WriteLine("-----------------------------------");
        }

        /// <summary>
        /// Initializes a JsonTextWriter with the initial JSON format needed for SharpHound output
        /// </summary>
        /// <param name="baseName"></param>
        /// <returns></returns>
        private class JsonFileWriter
        {
            private int Count { get; set; }
            private JsonTextWriter JsonWriter { get; }

            private readonly string _baseFileName;

            private static readonly JsonSerializer Serializer = new JsonSerializer
            {
                NullValueHandling = NullValueHandling.Include
            };

            internal JsonFileWriter(string baseFilename)
            {
                Count = 0;
                JsonWriter = CreateFile(baseFilename);
                _baseFileName = baseFilename;
            }

            internal void CloseWriter()
            {
                JsonWriter.Flush();
                JsonWriter.WriteEndArray();
                JsonWriter.WritePropertyName("meta");
                JsonWriter.WriteStartObject();
                JsonWriter.WritePropertyName("count");
                JsonWriter.WriteValue(Count);
                JsonWriter.WritePropertyName("type");
                JsonWriter.WriteValue(_baseFileName);
                JsonWriter.WritePropertyName("version");
                JsonWriter.WriteValue(3);
                JsonWriter.WriteEndObject();
                JsonWriter.Close();
            }

            internal void WriteObject(LdapWrapper json)
            {
                Serializer.Serialize(JsonWriter, json);
                Count++;
                if (Count % 100 == 0)
                    JsonWriter.Flush();
            }

            private static JsonTextWriter CreateFile(Context context, string baseName)
            {
                var filename = context.ResolveFileName(context, baseName, "json", true);
                UsedFileNames.Add(filename);

                var exists = File.Exists(filename);
                if (exists)
                {
                    throw new FileExistsException($"File {filename} already exists. This should never happen!");
                }

                var writer = new StreamWriter(filename, false, Encoding.UTF8);
                var jsonFormat = context.Flags.PrettyJson ? Formatting.Indented : Formatting.None;

                var jsonWriter = new JsonTextWriter(writer) { Formatting = jsonFormat };
                jsonWriter.WriteStartObject();
                jsonWriter.WritePropertyName(baseName);
                jsonWriter.WriteStartArray();

                return jsonWriter;
            }

        }
    }
}

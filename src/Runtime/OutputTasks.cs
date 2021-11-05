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
using System.Xml;
using SharpHound.Producers;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using Group = SharpHoundCommonLib.OutputTypes.Group;

namespace SharpHound.Core.Behavior
{
    public class OutputTasks
    {
        // private static readonly List<string> UsedFileNames = new List<string>();
        // private static readonly List<string> ZipFileNames = new List<string>();
        // private static Lazy<JsonFileWriter> _userOutput;
        // private static Lazy<JsonFileWriter> _groupOutput;
        // private static Lazy<JsonFileWriter> _computerOutput;
        // private static Lazy<JsonFileWriter> _domainOutput;
        // private static Lazy<JsonFileWriter> _gpoOutput;
        // private static Lazy<JsonFileWriter> _ouOutput;
        // private static int _lastCount;
        // private static int _currentCount;
        // private static Timer _statusTimer;
        // private static Stopwatch _runTimer;
        // private static Task _computerStatusTask;
        //
        // public static readonly ConcurrentDictionary<string, int> ComputerStatusCount =
        //     new ConcurrentDictionary<string, int>();
        //
        // public static readonly BlockingCollection<ComputerStatus> ComputerStatusQueue =
        //     new BlockingCollection<ComputerStatus>();
        //
        // public static readonly Lazy<string> ZipPasswords = new Lazy<string>(GenerateZipPassword);
        //
        // public static ConcurrentDictionary<string, string> SeenCommonPrincipals =
        //     new ConcurrentDictionary<string, string>();
        //
        // public OutputTasks(Context context)
        // {
        //     _userOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "users"));
        //     _groupOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "groups"));
        //     _computerOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "computers"));
        //     _domainOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "domains"));
        //     _gpoOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "gpos"));
        //     _ouOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "ous"));
        // }
        //
        // public static void PrintStatus()
        // {
        //     Console.WriteLine(
        //         _runTimer != null
        //             ? $"Status: {_currentCount} objects finished (+{_currentCount - _lastCount} {(float)_currentCount / (_runTimer.ElapsedMilliseconds / 1000)})/s -- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024} MB RAM"
        //             : $"Status: {_currentCount} objects finished (+{_currentCount - _lastCount}) -- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024} MB RAM");
        // }
        //
        // public static void WriteJsonOutput(LdapWrapper output) //TODO: update this call.
        // {
        //     throw new NotImplementedException("Update LDAP wrapper call");
        //     // switch (output)
        //     // {
        //     //     case Domain domain:
        //     //         _domainOutput.Value.WriteObject(output);
        //     //         break;
        //     //     case GPO gpo:
        //     //         _gpoOutput.Value.WriteObject(gpo);
        //     //         break;
        //     //     case Group group:
        //     //         _groupOutput.Value.WriteObject(group);
        //     //         break;
        //     //     case OU ou:
        //     //         _ouOutput.Value.WriteObject(ou);
        //     //         break;
        //     //     case User user:
        //     //         _userOutput.Value.WriteObject(user);
        //     //         break;
        //     // }
        //
        //     _currentCount++;
        // }
        //
        // public static async Task CompleteOutput(Context context)
        // {
        //     PrintStatus();
        //     Console.WriteLine($"Enumeration finished in {_runTimer.Elapsed}");
        //
        //     if (context.Flags.DumpComputerStatus)
        //     {
        //         CompleteComputerStatusOutput();
        //         await _computerStatusTask;
        //     }
        //
        //     var domainName = ClientHelpers.NormalizeDomainName(context, context.DomainName);
        //     var forestName = ClientHelpers.GetForestName(domainName).ToUpper();
        //     var dcSids = BaseProducer.GetDomainControllers();
        //     var domainSid = new SecurityIdentifier(dcSids.First().Key).AccountDomainSid.Value.ToUpper();
        //     var enterpriseDomainControllers = new Group
        //     {
        //         ObjectIdentifier = $"{forestName}-S-1-5-9",
        //         Members = BaseProducer.GetDomainControllers().Keys
        //             .Select(sid => new TypedPrincipal(sid, Label.Computer)).ToArray()
        //     };
        //
        //     enterpriseDomainControllers.Properties.Add("name", $"ENTERPRISE DOMAIN CONTROLLERS@{forestName}");
        //     enterpriseDomainControllers.Properties.Add("domain", forestName);
        //
        //     _groupOutput.Value.WriteObject(enterpriseDomainControllers);
        //
        //     var members = new[]
        //     {
        //         new TypedPrincipal($"{domainSid}-515", Label.Group),
        //         new TypedPrincipal($"{domainSid}-513", Label.Group)
        //     };
        //
        //     var everyone = new Group
        //     {
        //         ObjectIdentifier = $"{domainName}-S-1-1-0",
        //         Members = members
        //     };
        //
        //     everyone.Properties.Add("name", $"EVERYONE@{domainName}");
        //     everyone.Properties.Add("domain", domainName);
        //
        //     _groupOutput.Value.WriteObject(everyone);
        //
        //     var authUsers = new Group
        //     {
        //         ObjectIdentifier = $"{domainName}-S-1-5-11",
        //         Members = members
        //     };
        //
        //     authUsers.Properties.Add("name", $"AUTHENTICATED USERS@{domainName}");
        //     authUsers.Properties.Add("domain", domainName);
        //
        //     _groupOutput.Value.WriteObject(authUsers);
        //
        //     //Write objects for common principals
        //     foreach (var seen in SeenCommonPrincipals)
        //     {
        //         var domain = seen.Key;
        //         var sid = seen.Value;
        //
        //         context.LDAPUtils.GetWellKnownPrincipal(sid, domain, out var principal);
        //
        //         switch (principal.ObjectType)
        //         {
        //             case Label.User:
        //                 var u = new User
        //                 {
        //                     ObjectIdentifier = principal.ObjectIdentifier
        //                 };
        //                 u.Properties.Add("name", $"{principal.ObjectIdentifier}@{domain}".ToUpper());
        //                 u.Properties.Add("domain", domain);
        //                 _userOutput.Value.WriteObject(u);
        //                 break;
        //             case Label.Computer:
        //                 var c = new Computer
        //                 {
        //                     ObjectIdentifier = sid
        //                 };
        //
        //                 c.Properties.Add("name", $"{principal.ObjectIdentifier}@{domain}".ToUpper());
        //                 c.Properties.Add("domain", domain);
        //                 _computerOutput.Value.WriteObject(c);
        //                 break;
        //             case Label.Group:
        //                 var g = new Group
        //                 {
        //                     ObjectIdentifier = sid
        //                 };
        //                 g.Properties.Add("name", $"{principal.ObjectIdentifier}@{domain}".ToUpper());
        //                 g.Properties.Add("domain", domain);
        //                 _groupOutput.Value.WriteObject(g);
        //                 break;
        //             default:
        //                 throw new ArgumentOutOfRangeException();
        //         }
        //     }
        //
        //     _runTimer.Stop();
        //     _statusTimer.Stop();
        //     if (_userOutput.IsValueCreated)
        //         _userOutput.Value.CloseWriter();
        //     if (_computerOutput.IsValueCreated)
        //         _computerOutput.Value.CloseWriter();
        //     if (_groupOutput.IsValueCreated)
        //         _groupOutput.Value.CloseWriter();
        //     if (_domainOutput.IsValueCreated)
        //         _domainOutput.Value.CloseWriter();
        //     if (_gpoOutput.IsValueCreated)
        //         _gpoOutput.Value.CloseWriter();
        //     if (_ouOutput.IsValueCreated)
        //         _ouOutput.Value.CloseWriter();
        //
        //     _userOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "users"), false);
        //     _groupOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "groups"), false);
        //     _computerOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "computers"), false);
        //     _domainOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "domains"), false);
        //     _gpoOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "gpos"), false);
        //     _ouOutput = new Lazy<JsonFileWriter>(() => new JsonFileWriter(context, "ous"), false);
        //
        //     string finalName;
        //
        //     if (context.Flags.NoZip || context.Flags.NoOutput)
        //         return;
        //
        //     if (context.ZipFilename != null)
        //         finalName = _context.ResolveFileName(context.ZipFilename, "zip", true);
        //     else
        //         finalName = _context.ResolveFileName("BloodHound", "zip", true);
        //
        //     Console.WriteLine($"Compressing data to {finalName}");
        //
        //     var buffer = new byte[4096];
        //
        //     if (File.Exists(finalName))
        //     {
        //         Console.WriteLine("Zip File already exists, randomizing filename");
        //         finalName = _context.ResolveFileName(Path.GetRandomFileName(), "zip", true);
        //         Console.WriteLine($"New filename is {finalName}");
        //     }
        //
        //     using (var zipStream = new ZipOutputStream(File.Create(finalName)))
        //     {
        //         //Set level to 9, maximum compressions
        //         zipStream.SetLevel(9);
        //
        //         if (context.Flags.EncryptZip)
        //         {
        //             if (!context.Flags.Loop)
        //             {
        //                 var password = ZipPasswords.Value;
        //                 zipStream.Password = password;
        //
        //                 Console.WriteLine(
        //                     $"Password for Zip file is {password}. Unzip files manually to upload to interface");
        //             }
        //         }
        //         else
        //         {
        //             Console.WriteLine("You can upload this file directly to the UI");
        //         }
        //
        //         foreach (var file in UsedFileNames)
        //         {
        //             var entry = new ZipEntry(Path.GetFileName(file)) { DateTime = DateTime.Now };
        //             zipStream.PutNextEntry(entry);
        //
        //             using (var fileStream = File.OpenRead(file))
        //             {
        //                 int source;
        //                 do
        //                 {
        //                     source = await fileStream.ReadAsync(buffer, 0, buffer.Length);
        //                     zipStream.Write(buffer, 0, source);
        //                 } while (source > 0);
        //             }
        //
        //             File.Delete(file);
        //         }
        //
        //         zipStream.Finish();
        //     }
        //
        //     if (context.Flags.Loop)
        //         ZipFileNames.Add(finalName);
        //
        //     UsedFileNames.Clear();
        // }
        //
        // public static async Task CollapseLoopZipFiles(Context context)
        // {
        //     if (context.Flags.NoOutput || context.Flags.NoZip)
        //         return;
        //
        //     var finalName = ClientHelpers.GetLoopFileName(context);
        //
        //     Console.WriteLine($"Compressing zip files to {finalName}");
        //
        //     var buffer = new byte[4096];
        //
        //     if (File.Exists(finalName))
        //     {
        //         Console.WriteLine("Zip File already exists, randomizing filename");
        //         finalName = ClientHelpers.ResolveFileName(context, Path.GetRandomFileName(), "zip", true);
        //         Console.WriteLine($"New filename is {finalName}");
        //     }
        //
        //     using (var zipStream = new ZipOutputStream(File.Create(finalName)))
        //     {
        //         //Set level to 0, since we're just storing the other zips
        //         zipStream.SetLevel(0);
        //
        //         if (context.Flags.EncryptZip)
        //         {
        //             var password = ZipPasswords.Value;
        //             zipStream.Password = password;
        //             Console.WriteLine(
        //                 $"Password for zip file is {password}. Unzip files manually to upload to interface");
        //         }
        //         else
        //         {
        //             Console.WriteLine("Unzip the zip file and upload the other zips to the interface");
        //         }
        //
        //         foreach (var file in ZipFileNames)
        //         {
        //             var entry = new ZipEntry(Path.GetFileName(file)) { DateTime = DateTime.Now };
        //             zipStream.PutNextEntry(entry);
        //
        //             using (var fileStream = File.OpenRead(file))
        //             {
        //                 int source;
        //                 do
        //                 {
        //                     source = await fileStream.ReadAsync(buffer, 0, buffer.Length);
        //                     zipStream.Write(buffer, 0, source);
        //                 } while (source > 0);
        //             }
        //
        //             File.Delete(file);
        //         }
        //
        //         zipStream.Finish();
        //     }
        // }
        //
        // private static string GenerateZipPassword()
        // {
        //     const string space = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        //     var builder = new StringBuilder();
        //     var random = new Random();
        //     for (var i = 0; i < 10; i++) builder.Append(space[random.Next(space.Length)]);
        //     return builder.ToString();
        // }
        //
        // public static void StartComputerStatusTask(Context context)
        // {
        //     if (!context.Flags.DumpComputerStatus)
        //     {
        //         _computerStatusTask = null;
        //         return;
        //     }
        //
        //     _computerStatusTask = Task.Factory.StartNew(() =>
        //     {
        //         var fileName = ClientHelpers.ResolveFileName(context, "computerstatus", "csv", true);
        //         UsedFileNames.Add(fileName);
        //         var count = 0;
        //         using (var writer = new StreamWriter(fileName, false))
        //         {
        //             writer.WriteLine("ComputerName, Task, Status");
        //             foreach (var status in ComputerStatusQueue.GetConsumingEnumerable())
        //             {
        //                 writer.WriteLine(status.Error);
        //                 count++;
        //                 if (count % 100 == 0)
        //                     writer.Flush();
        //             }
        //
        //             writer.Flush();
        //         }
        //     }, TaskCreationOptions.LongRunning);
        // }
        //
        // public static void AddComputerStatus(ComputerStatus status)
        // {
        //     ComputerStatusQueue.Add(status);
        //     var hash =
        //         $"{status.GetHashCode()}-{Regex.Replace(status.ToString(), @"\t|\n|\r", "")}"; // TODO: How should this be calculated.
        //     ComputerStatusCount.AddOrUpdate(hash, 1, (id, count) => count + 1);
        // }
        //
        // private static void CompleteComputerStatusOutput()
        // {
        //     ComputerStatusQueue.CompleteAdding();
        //     Console.WriteLine();
        //     Console.WriteLine("-------Computer Status Count-------");
        //     foreach (var key in ComputerStatusCount) Console.WriteLine($"{key.Key}: {key.Value}");
        //     Console.WriteLine("-----------------------------------");
        // }
        //
        // /// <summary>
        // ///     Initializes a JsonTextWriter with the initial JSON format needed for SharpHound output
        // /// </summary>
        // /// <param name="baseName"></param>
        // /// <returns></returns>
        // private class JsonFileWriter
        // {
        //     private static readonly JsonSerializer Serializer = new JsonSerializer
        //     {
        //         NullValueHandling = NullValueHandling.Include
        //     };
        //
        //     private readonly string _baseFileName;
        //
        //     public JsonFileWriter(Context context, string baseFilename)
        //     {
        //         Count = 0;
        //         JsonWriter = CreateFile(context, baseFilename);
        //         _baseFileName = baseFilename;
        //     }
        //
        //     private int Count { get; set; }
        //     private JsonTextWriter JsonWriter { get; }
        //
        //     public void CloseWriter()
        //     {
        //         JsonWriter.Flush();
        //         JsonWriter.WriteEndArray();
        //         JsonWriter.WritePropertyName("meta");
        //         JsonWriter.WriteStartObject();
        //         JsonWriter.WritePropertyName("count");
        //         JsonWriter.WriteValue(Count);
        //         JsonWriter.WritePropertyName("type");
        //         JsonWriter.WriteValue(_baseFileName);
        //         JsonWriter.WritePropertyName("version");
        //         JsonWriter.WriteValue(3);
        //         JsonWriter.WriteEndObject();
        //         JsonWriter.Close();
        //     }
        //
        //     public void WriteObject<T>(T json)
        //     {
        //         Serializer.Serialize(JsonWriter, json);
        //         Count++;
        //         if (Count % 100 == 0)
        //             JsonWriter.Flush();
        //     }
        //
        //     public static JsonTextWriter CreateFile(Context context, string baseName)
        //     {
        //         var filename = ClientHelpers.ResolveFileName(context, baseName, "json", true);
        //         UsedFileNames.Add(filename);
        //
        //         var exists = File.Exists(filename);
        //         if (exists) throw new FileExistsException($"File {filename} already exists. This should never happen!");
        //
        //         var writer = new StreamWriter(filename, false, Encoding.UTF8);
        //         var jsonFormat = context.Flags.PrettyJson ? Formatting.Indented : Formatting.None;
        //
        //         var jsonWriter = new JsonTextWriter(writer) { Formatting = jsonFormat };
        //         jsonWriter.WriteStartObject();
        //         jsonWriter.WritePropertyName(baseName);
        //         jsonWriter.WriteStartArray();
        //
        //         return jsonWriter;
        //     }
        // }
    }
}
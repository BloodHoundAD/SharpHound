using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHound.Core.Behavior;
using SharpHoundCommonLib;

namespace SharpHound.Producers
{
    /// <summary>
    ///     Substitute producer for the ComputerFile option
    /// </summary>
    internal class ComputerFileProducer : BaseProducer
    {
        /// <summary>
        ///     Grabs computers names from the text file specified in the options, and attempts to resolve them to LDAP objects.
        ///     Pushes the corresponding LDAP objects to the queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        public override async Task Produce()
        {
            var computerFile = _context.ComputerFile;
            var cancellationToken = _context.CancellationTokenSource.Token;

            var ldapData = CreateLDAPData();

            try
            {
                //Open the file for reading
                using var fileStream = new StreamReader(new FileStream(computerFile, FileMode.Open, FileAccess.Read));
                string computer;
                // Loop over each line in the file
                while ((computer = await fileStream.ReadLineAsync()) != null)
                {
                    //If the cancellation token is set, cancel enumeration
                    if (cancellationToken.IsCancellationRequested) break;

                    string sid;
                    if (!computer.StartsWith("S-1-5-21"))
                        //The computer isn't a SID so try to convert it to one
                        sid = await _context.LDAPUtils.ResolveHostToSid(computer, _context.DomainName);
                    else
                        //The computer is already a sid, so just store it off
                        sid = computer;

                    try
                    {
                        //Convert the sid to a hex representation and find the entry in the domain
                        var hexSid = Helpers.ConvertSidToHexSid(sid);
                        var entry = _context.LDAPUtils.QueryLDAP($"(objectsid={hexSid})", SearchScope.Subtree,
                            ldapData.Props.ToArray(), cancellationToken, _context.DomainName, adsPath:_context.SearchBase).DefaultIfEmpty(null).FirstOrDefault();
                        if (entry == null)
                        {
                            //We couldn't find the entry for whatever reason
                            _context.Logger.LogWarning("Failed to resolve {computer}", computer);
                            continue;
                        }

                        //Success! Send the computer to be processed
                        await _channel.Writer.WriteAsync(entry, cancellationToken);
                    }
                    catch (Exception e)
                    {
                        _context.Logger.LogWarning(e, "Failed to resolve {computer}", computer);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error opening ComputerFile: {e}");
            }
        }

        public ComputerFileProducer(Context context, Channel<ISearchResultEntry> channel) : base(context, channel)
        {
        }
    }
}
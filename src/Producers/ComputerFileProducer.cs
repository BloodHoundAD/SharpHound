using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;

namespace Sharphound.Producers
{
    /// <summary>
    ///     Substitute producer for the ComputerFile option
    /// </summary>
    internal class ComputerFileProducer : BaseProducer
    {
        public ComputerFileProducer(IContext context, Channel<ISearchResultEntry> channel, Channel<OutputBase> outputChannel) : base(context, channel, outputChannel)
        {
        }

        /// <summary>
        ///     Grabs computers names from the text file specified in the options, and attempts to resolve them to LDAP objects.
        ///     Pushes the corresponding LDAP objects to the queue.
        /// </summary>
        /// <returns></returns>
        public override async Task Produce()
        {
            var computerFile = Context.ComputerFile;
            var cancellationToken = Context.CancellationTokenSource.Token;

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
                        sid = await Context.LDAPUtils.ResolveHostToSid(computer, Context.DomainName);
                    else
                        //The computer is already a sid, so just store it off
                        sid = computer;

                    try
                    {
                        //Convert the sid to a hex representation and find the entry in the domain
                        var hexSid = Helpers.ConvertSidToHexSid(sid);
                        var entry = Context.LDAPUtils.QueryLDAP($"(objectsid={hexSid})", SearchScope.Subtree,
                            ldapData.Props.ToArray(), cancellationToken, Context.DomainName,
                            adsPath: Context.SearchBase).DefaultIfEmpty(null).FirstOrDefault();
                        if (entry == null)
                        {
                            //We couldn't find the entry for whatever reason
                            Context.Logger.LogWarning("Failed to resolve {computer}", computer);
                            continue;
                        }

                        //Success! Send the computer to be processed
                        await Channel.Writer.WriteAsync(entry, cancellationToken);
                    }
                    catch (Exception e)
                    {
                        Context.Logger.LogWarning(e, "Failed to resolve {computer}", computer);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error opening ComputerFile: {e}");
            }
        }
    }
}
using SharpHound.Core;
using SharpHoundCommonLib;
using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound.Producers
{
    /// <summary>
    /// Substitute producer for the ComputerFile option
    /// </summary>
    internal class ComputerFileProducer : BaseProducer
    {

        private Context _context;

        public ComputerFileProducer(Context context, string query, string[] props) : base(context, query, props)
        {
            _context = context;
        }

        /// <summary>
        /// Grabs computers names from the text file specified in the options, and attempts to resolve them to LDAP objects.
        /// Pushes the corresponding LDAP objects to the queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        protected override async Task ProduceLdap(ITargetBlock<ISearchResultEntry> queue)
        {
            var token = this.Context.CancellationTokenSource.Token;
            OutputTasks.StartOutputTimer();

            try
            {
                //Open the file for reading
                using (var fileStream = new StreamReader(new FileStream(this.Context.ComputerFile, FileMode.Open, FileAccess.Read)))
                {
                    string computer;
                    // Loop over each line in the file
                    while ((computer = fileStream.ReadLine()) != null)
                    {
                        //If the cancellation token is set, cancel enumeration
                        if (token.IsCancellationRequested)
                        {
                            break;
                        }

                        string sid;
                        if (!computer.StartsWith("S-1-5-21"))
                        {
                            //The computer isn't a SID so try to convert it to one
                            sid = this.Context.LDAPUtils.ResolveHostToSid(computer, DomainName).Result;
                        }
                        else
                        {
                            //The computer is already a sid, so just store it off
                            sid = computer;
                        }

                        try
                        {
                            //Convert the sid to a hex representation and find the entry in the domain
                            var hexSid = Helpers.ConvertSidToHexSid(sid);
                            var entry = await Searcher.GetOne($"(objectsid={hexSid})", Props, SearchScope.Subtree);
                            if (entry == null)
                            {
                                //We couldn't find the entry for whatever reason
                                Console.WriteLine($"Failed to resolve {computer}");
                                continue;
                            }

                            //Success! Send the computer to be processed
                            await queue.SendAsync(entry);
                        }
                        catch
                        {
                            Console.WriteLine($"Failed to resolve {computer}");
                        }
                    }
                }
            }
            catch
            {
                Console.WriteLine($"Error in opening file {this.Context.ComputerFile}");
            }
            finally
            {
                queue.Complete();
            }
        }
    }
}

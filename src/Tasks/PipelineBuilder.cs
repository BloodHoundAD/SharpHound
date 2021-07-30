using SharpHound.Core;
using SharpHound.LdapWrappers;
using SharpHound.Producers;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound.Tasks
{
    /// <summary>
    /// Creates the enumeration pipeline
    /// </summary>
    internal class PipelineBuilder
    {
        internal static Task GetBasePipelineForDomain(Context context)
        {
            var resolvedMethods = context.ResolvedCollectionMethods;
            var ldapVariables = LdapBuilder.BuildLdapQuery(resolvedMethods);
            BaseProducer producer;
            if (context.Flags.Stealth)
            {
                producer = new StealthProducer(context, ldapVariables.LdapFilter, ldapVariables.LdapProperties);
            }
            else if (context.ComputerFile != null)
            {
                producer = new ComputerFileProducer(context, null, ldapVariables.LdapProperties);
            }
            else
            {
                producer = new LdapProducer(context, ldapVariables.LdapFilter, ldapVariables.LdapProperties);
            }

            var linkOptions = new DataflowLinkOptions
            {
                PropagateCompletion = true
            };

            var executionOptions = new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false,
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 500
            };

            //Store our blocks in a list for linking
            var blocks = new List<TransformBlock<LdapWrapper, LdapWrapper>>();

            //The first block will always convert searchresults to the wrapper object
            var findTypeBlock = new TransformBlock<ISearchResultEntry, LdapWrapper>(ConvertToWrapperTasks.CreateLdapWrapper, new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false,
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 500
            });

            //Link null wrappers to a nulltarget block. We don't do anything with them
            findTypeBlock.LinkTo(DataflowBlock.NullTarget<LdapWrapper>(), item => item == null);

            //Keep this variable to make instantiation easy
            TransformBlock<LdapWrapper, LdapWrapper> block = null;

            //Start with pure LDAP collection methods
            if ((resolvedMethods & ResolvedCollectionMethod.ACL) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ACLTasks.ProcessAces, executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.Group) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(GroupEnumerationTasks.ProcessGroupMembership,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ObjectPropertyTasks.ResolveObjectProperties,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.Container) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ContainerTasks.EnumerateContainer,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.GPOLocalGroup) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(GPOGroupTasks.ParseGPOLocalGroups,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.SPNTargets) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(SPNTasks.ProcessSPNS, executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.Trusts) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(TrustTasks.ResolveDomainTrusts, executionOptions);
                blocks.Add(block);
            }

            //Start computer block

            //Only add this block if there's actually computer collection happening 
            if (context.IsComputerCollectionSet())
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ComputerAvailableTasks.CheckSMBOpen,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.Session) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(NetSessionTasks.ProcessNetSessions,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.RDP) != 0 || (resolvedMethods & ResolvedCollectionMethod.DCOM) != 0 ||
                (resolvedMethods & ResolvedCollectionMethod.LocalAdmin) != 0 ||
                (resolvedMethods & ResolvedCollectionMethod.PSRemote) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(LocalGroupTasks.GetLocalGroupMembers,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.LoggedOn) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(LoggedOnTasks.ProcessLoggedOn, executionOptions);
                blocks.Add(block);
            }

            if (blocks.Count == 0)
            {
                findTypeBlock.Complete();
                return findTypeBlock.Completion;
            }

            var linked = false;
            foreach (var toLink in blocks)
            {
                if (!linked)
                {
                    findTypeBlock.LinkTo(toLink, linkOptions, item => item != null);
                    linked = true;
                }
                else
                {
                    block.LinkTo(toLink, linkOptions, item => item != null);
                }
                block = toLink;
            }

            ITargetBlock<LdapWrapper> outputBlock;
            if (context.Flags.NoOutput)
            {
                outputBlock = new ActionBlock<LdapWrapper>(wrapper =>
                {
                    //Do nothing
                }, executionOptions);
            }
            else
            {
                //The output block should only have a single thread for writing to prevent issues
                outputBlock = new ActionBlock<LdapWrapper>(OutputTasks.WriteJsonOutput, new ExecutionDataflowBlockOptions
                {
                    BoundedCapacity = 500,
                    MaxDegreeOfParallelism = 1,
                    EnsureOrdered = false
                });
            }

            block.LinkTo(outputBlock, linkOptions);
            producer.StartProducer(findTypeBlock);
            return outputBlock.Completion;
        }

        internal static Task GetLoopPipelineForDomain(Context context)
        {
            var resolvedMethods = context.GetLoopCollectionMethods();
            context.StartNewRun();
            var ldapVariables = LdapBuilder.BuildLdapQuery(resolvedMethods);
            BaseProducer producer;
            if (context.Flags.Stealth)
            {
                producer = new StealthProducer(context, ldapVariables.LdapFilter, ldapVariables.LdapProperties);
            }
            else
            {
                producer = new LdapProducer(context, ldapVariables.LdapFilter, ldapVariables.LdapProperties);
            }

            var linkOptions = new DataflowLinkOptions
            {
                PropagateCompletion = true
            };

            var executionOptions = new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false,
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 500
            };

            //Store our blocks in a list for linking
            var blocks = new List<TransformBlock<LdapWrapper, LdapWrapper>>();

            var findTypeBlock = new TransformBlock<ISearchResultEntry, LdapWrapper>(ConvertToWrapperTasks.CreateLdapWrapper, new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false,
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 500
            });

            findTypeBlock.LinkTo(DataflowBlock.NullTarget<LdapWrapper>(), item => item == null);

            //Keep this variable to make instantiation easy
            TransformBlock<LdapWrapper, LdapWrapper> block = null;


            if (!context.Flags.SkipPortScan && context.IsComputerCollectionSet())
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ComputerAvailableTasks.CheckSMBOpen,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.Session) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(NetSessionTasks.ProcessNetSessions,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.RDP) != 0 || (resolvedMethods & ResolvedCollectionMethod.DCOM) != 0 ||
                (resolvedMethods & ResolvedCollectionMethod.LocalAdmin) != 0 ||
                (resolvedMethods & ResolvedCollectionMethod.PSRemote) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(LocalGroupTasks.GetLocalGroupMembers,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & ResolvedCollectionMethod.LoggedOn) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(LoggedOnTasks.ProcessLoggedOn, executionOptions);
                blocks.Add(block);
            }

            if (blocks.Count == 0)
            {
                findTypeBlock.Complete();
                return findTypeBlock.Completion;
            }

            var linked = false;
            foreach (var toLink in blocks)
            {
                if (!linked)
                {
                    findTypeBlock.LinkTo(toLink, linkOptions, item => item != null);
                    linked = true;
                }
                else
                {
                    block.LinkTo(toLink, linkOptions, item => item != null);
                }
                block = toLink;
            }

            ITargetBlock<LdapWrapper> outputBlock;
            if (context.Flags.NoOutput)
            {
                outputBlock = new ActionBlock<LdapWrapper>(wrapper =>
                {
                    //Do nothing
                }, executionOptions);
            }
            else
            {
                //The output block should only have a single thread for writing to prevent issues
                outputBlock = new ActionBlock<LdapWrapper>(OutputTasks.WriteJsonOutput, new ExecutionDataflowBlockOptions
                {
                    BoundedCapacity = 500,
                    MaxDegreeOfParallelism = 1,
                    EnsureOrdered = false
                });
            }

            block.LinkTo(outputBlock, linkOptions);
            producer.StartProducer(findTypeBlock);
            return outputBlock.Completion;
        }

    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RegionOrebroLan.Security.Principal;

namespace IntegrationTests
{
	[TestClass]
	public class WindowsGroupsProviderTest
	{
		#region Methods

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public async Task GetGroups_IfTheUserPrincipalNameParameterIsEmpty_ShouldThrowAnArgumentException()
		{
			await Task.CompletedTask;

			var _ = new WindowsGroupsProvider().GetGroups(false, false, string.Empty);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public async Task GetGroups_IfTheUserPrincipalNameParameterIsNull_ShouldThrowAnArgumentNullException()
		{
			await Task.CompletedTask;

			var _ = new WindowsGroupsProvider().GetGroups(false, false, (string)null);
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public async Task GetGroups_IfTheUserPrincipalNameParameterIsWhitespacesOnly_ShouldThrowAnArgumentException()
		{
			await Task.CompletedTask;

			var _ = new WindowsGroupsProvider().GetGroups(false, false, "   ");
		}

		[TestMethod]
		[SuppressMessage("Design", "CA1031:Do not catch general exception types")]
		public async Task GetGroups_Test()
		{
			await Task.CompletedTask;

			using(var userPrincipal = UserPrincipal.Current)
			{
				if(userPrincipal.Context.ContextType != ContextType.Domain)
					Assert.Inconclusive("Test can only be run with a domain-account.");

				var domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName.Split('.')[0].ToUpperInvariant();
				var machineName = Environment.MachineName;

				var groupPrincipals = new Dictionary<GroupPrincipal, string>();

				foreach(var groupPrincipal in userPrincipal.GetAuthorizationGroups().Cast<GroupPrincipal>())
				{
					string name;

					try
					{
						name = groupPrincipal.Sid.Translate(typeof(NTAccount)).Value;
					}
					catch
					{
						name = string.Empty;
					}

					groupPrincipals.Add(groupPrincipal, name);
				}

				var domainGroupPrincipals = groupPrincipals.Where(group => group.Value.StartsWith($"{domainName}\\", StringComparison.OrdinalIgnoreCase)).ToArray();
				var machineGroupPrincipals = groupPrincipals.Where(group => group.Value.StartsWith($"{machineName}\\", StringComparison.OrdinalIgnoreCase)).ToArray();

				var expectedAllGroupsCount = groupPrincipals.Count;
				var expectedBuiltInAndDomainGroupsCount = groupPrincipals.Count - machineGroupPrincipals.Length;
				var expectedDomainGroupsCount = domainGroupPrincipals.Length;
				var expectedDomainAndMachineGroupsCount = domainGroupPrincipals.Length + machineGroupPrincipals.Length;

				var userPrincipalName = userPrincipal.UserPrincipalName;
				var windowsGroupsProvider = new WindowsGroupsProvider();

				var allGroups = windowsGroupsProvider.GetGroups(true, true, userPrincipalName);
				Assert.AreEqual(expectedAllGroupsCount, allGroups.Count);

				var builtInAndDomainGroups = windowsGroupsProvider.GetGroups(true, false, userPrincipalName);
				Assert.AreEqual(expectedBuiltInAndDomainGroupsCount, builtInAndDomainGroups.Count);

				var domainAndMachineGroups = windowsGroupsProvider.GetGroups(false, true, userPrincipalName);
				Assert.AreEqual(expectedDomainAndMachineGroupsCount, domainAndMachineGroups.Count);

				var domainGroups = windowsGroupsProvider.GetGroups(false, false, userPrincipalName);
				Assert.AreEqual(expectedDomainGroupsCount, domainGroups.Count);
			}
		}

		#endregion
	}
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using RegionOrebroLan.DependencyInjection;

namespace RegionOrebroLan.Security.Principal
{
	[ServiceConfiguration(ServiceType = typeof(IWindowsGroupsProvider))]
	public class WindowsGroupsProvider : IWindowsGroupsProvider
	{
		#region Methods

		public virtual ISet<string> GetGroups(bool builtInGroups, bool machineGroups, string userPrincipalName)
		{
			if(userPrincipalName == null)
				throw new ArgumentNullException(nameof(userPrincipalName));

			if(userPrincipalName.Length == 0)
				throw new ArgumentException("The user-principal-name can not be empty.", nameof(userPrincipalName));

			if(userPrincipalName.Trim().Length == 0)
				throw new ArgumentException("The user-principal-name can not contain whitespaces only.", nameof(userPrincipalName));

			using(var windowsIdentity = new WindowsIdentity(userPrincipalName))
			{
				return this.GetGroups(builtInGroups, machineGroups, windowsIdentity);
			}
		}

		public virtual ISet<string> GetGroups(bool builtInGroups, IIdentity identity, bool machineGroups)
		{
			// ReSharper disable All

			if(identity == null)
				throw new ArgumentNullException(nameof(identity));

			// ReSharper restore All

			if(identity is WindowsIdentity windowsIdentity)
				return this.GetGroups(builtInGroups, machineGroups, windowsIdentity);

			return new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
		}

		public virtual ISet<string> GetGroups(bool builtInGroups, bool machineGroups, WindowsIdentity windowsIdentity)
		{
			if(windowsIdentity == null)
				throw new ArgumentNullException(nameof(windowsIdentity));

			// ReSharper disable AssignNullToNotNullAttribute

			var securityIdentifiers = windowsIdentity.Groups.Cast<SecurityIdentifier>();

			if(!builtInGroups)
				securityIdentifiers = securityIdentifiers.Where(securityIdentifier => securityIdentifier.AccountDomainSid != null);

			var identityReferences = new IdentityReferenceCollection();

			foreach(var securityIdentifier in securityIdentifiers)
			{
				identityReferences.Add(securityIdentifier);
			}

			var groups = identityReferences.Translate(typeof(NTAccount)).Select(ntAccount => ntAccount.Value);

			if(!machineGroups)
				groups = groups.Where(group => !group.StartsWith($"{Environment.MachineName}\\", StringComparison.OrdinalIgnoreCase));

			return new SortedSet<string>(groups, StringComparer.OrdinalIgnoreCase);

			// ReSharper restore AssignNullToNotNullAttribute
		}

		#endregion
	}
}
using System.Collections.Generic;
using System.Security.Principal;

namespace RegionOrebroLan.Security.Principal
{
	public interface IWindowsGroupsProvider
	{
		#region Methods

		ISet<string> GetGroups(bool builtInGroups, bool machineGroups, string userPrincipalName);
		ISet<string> GetGroups(bool builtInGroups, IIdentity identity, bool machineGroups);

		#endregion
	}
}
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace GPOwned.Shared
{
    public static class AdHelper
    {
        // ── Alternate credentials ────────────────────────────────────────────
        private static string _credUser;
        private static string _credPass;
        private static string _targetDomain;

        public static void SetCredentials(string username, string password)
        {
            _credUser = username;
            _credPass = password;
        }

        public static void SetTargetDomain(string domain)
        {
            _targetDomain = domain;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain,
            string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        // LOGON32_LOGON_NEW_CREDENTIALS (9) + LOGON32_PROVIDER_WINNT50 (3):
        // creates a network-only token (like runas /netonly) — outbound UNC/SMB uses
        // the supplied creds while the local process identity stays unchanged.
        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        private const int LOGON32_PROVIDER_WINNT50       = 3;

        // Returns an impersonation context for UNC/SYSVOL access, or null if no creds set.
        public static WindowsImpersonationContext BeginNetworkImpersonation()
        {
            if (string.IsNullOrEmpty(_credUser)) return null;

            string user = _credUser, domain = null;
            if (user.Contains("\\"))
            {
                int slash = user.IndexOf('\\');
                domain = user.Substring(0, slash);
                user   = user.Substring(slash + 1);
            }

            IntPtr token;
            if (!LogonUser(user, domain, _credPass,
                           LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, out token))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed");

            try   { return new WindowsIdentity(token).Impersonate(); }
            finally { CloseHandle(token); }
        }

        // Creates a DirectoryEntry with alternate credentials when set.
        private static DirectoryEntry MakeEntry(string path)
        {
            if (!string.IsNullOrEmpty(_credUser))
                return new DirectoryEntry(path, _credUser, _credPass, AuthenticationTypes.Secure);
            return new DirectoryEntry(path);
        }

        // Builds an LDAP path; prepends the target domain server when set so that
        // cross-domain queries route to the right DC.
        private static string LdapPath(string dn)
        {
            if (!string.IsNullOrEmpty(_targetDomain))
                return "LDAP://" + _targetDomain + "/" + dn;
            return "LDAP://" + dn;
        }

        // ── Domain info ──────────────────────────────────────────────────────

        // Queries the current forest's RootDSE (original behaviour).
        public static void GetDomainInfo(out string domainFqdn, out string domainDN)
        {
            GetDomainInfo(null, out domainFqdn, out domainDN);
        }

        // When targetDomain is non-null, queries that domain's RootDSE directly.
        // domainFqdn is set to the target domain's own FQDN (not the forest root).
        public static void GetDomainInfo(string targetDomain, out string domainFqdn, out string domainDN)
        {
            string ldapPath = string.IsNullOrEmpty(targetDomain)
                ? "LDAP://RootDSE"
                : "LDAP://" + targetDomain + "/RootDSE";

            using (var rootDse = MakeEntry(ldapPath))
            {
                domainDN = rootDse.Properties["defaultNamingContext"].Value.ToString();
                if (string.IsNullOrEmpty(targetDomain))
                {
                    string rootDN = rootDse.Properties["rootDomainNamingContext"].Value.ToString();
                    domainFqdn = DnToFqdn(rootDN);
                }
                else
                {
                    domainFqdn = DnToFqdn(domainDN);
                }
            }
        }

        // "DC=domain,DC=local" → "domain.local"
        public static string DnToFqdn(string dn)
        {
            var parts = new List<string>();
            foreach (string part in dn.Split(','))
            {
                string trimmed = part.Trim();
                if (trimmed.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    parts.Add(trimmed.Substring(3));
            }
            return string.Join(".", parts);
        }

        // ── GPO resolution ───────────────────────────────────────────────────

        // Resolves GPO display name → CN GUID string (e.g. "{387547AA-...}")
        public static string ResolveGpoGuid(string gpoName, string domainDN)
        {
            using (var searchRoot = MakeEntry(LdapPath("CN=Policies,CN=System," + domainDN)))
            using (var searcher = new DirectorySearcher(searchRoot))
            {
                searcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=" + EscapeLdap(gpoName) + "))";
                searcher.SearchScope = SearchScope.OneLevel;
                searcher.PropertiesToLoad.Add("cn");
                var result = searcher.FindOne();
                if (result == null) return null;
                var val = result.Properties["cn"];
                if (val == null || val.Count == 0) return null;
                return val[0] != null ? val[0].ToString() : null;
            }
        }

        // Resolves a GPO GUID → display name.
        public static string ResolveGpoName(string guid, string domainDN)
        {
            try
            {
                using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
                {
                    entry.RefreshCache(new string[] { "displayName" });
                    var val = entry.Properties["displayName"].Value;
                    return val != null ? val.ToString() : "Unknown GPO";
                }
            }
            catch { return "Unknown GPO"; }
        }

        // ── ACL checks ───────────────────────────────────────────────────────

        public static bool CheckGpoWriteAccess(string guid, string domainDN)
        {
            string ignored;
            return CheckGpoWriteAccess(guid, domainDN, out ignored);
        }

        public static bool CheckGpoWriteAccess(string guid, string domainDN, out string writer)
        {
            writer = null;
            var writers = new List<string>();
            try
            {
                using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
                {
                    var rules = entry.ObjectSecurity.GetAccessRules(true, true, typeof(NTAccount));
                    string currentUser = Environment.UserName;

                    foreach (ActiveDirectoryAccessRule rule in rules)
                    {
                        string rightsStr = rule.ActiveDirectoryRights.ToString();
                        bool write =
                            rightsStr.IndexOf("GenericAll",    StringComparison.OrdinalIgnoreCase) >= 0 ||
                            rightsStr.IndexOf("GenericWrite",  StringComparison.OrdinalIgnoreCase) >= 0 ||
                            rightsStr.IndexOf("WriteDacl",     StringComparison.OrdinalIgnoreCase) >= 0 ||
                            rightsStr.IndexOf("WriteOwner",    StringComparison.OrdinalIgnoreCase) >= 0 ||
                            rightsStr.IndexOf("WriteProperty", StringComparison.OrdinalIgnoreCase) >= 0;

                        if (!write) continue;

                        string id = rule.IdentityReference.Value;

                        // When alternate credentials are set, check against that identity too.
                        string altUser = !string.IsNullOrEmpty(_credUser)
                            ? _credUser.TrimEnd('$')
                            : null;
                        bool relevant =
                            id.IndexOf(currentUser,           StringComparison.OrdinalIgnoreCase) >= 0 ||
                            id.IndexOf("Authenticated Users", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            id.IndexOf("Domain Users",        StringComparison.OrdinalIgnoreCase) >= 0 ||
                            id.IndexOf("Everyone",            StringComparison.OrdinalIgnoreCase) >= 0 ||
                            (altUser != null &&
                             id.IndexOf(altUser,              StringComparison.OrdinalIgnoreCase) >= 0);

                        if (relevant && !writers.Contains(id))
                            writers.Add(id);
                    }
                }
            }
            catch { }

            if (writers.Count > 0)
            {
                writer = string.Join(", ", writers.ToArray());
                return true;
            }
            return false;
        }

        // ── GPO property helpers ─────────────────────────────────────────────

        public static int GetGpoFlags(string guid, string domainDN)
        {
            using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
            {
                entry.RefreshCache(new string[] { "flags" });
                var val = entry.Properties["flags"].Value;
                return val != null ? (int)val : 0;
            }
        }

        public static void SetGpoFlags(string guid, string domainDN, int flags)
        {
            using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
            {
                entry.Properties["flags"].Value = flags;
                entry.CommitChanges();
            }
        }

        public static string GetGpoExtensionNames(string guid, string domainDN)
        {
            using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
            {
                entry.RefreshCache(new string[] { "gPCMachineExtensionNames" });
                var val = entry.Properties["gPCMachineExtensionNames"].Value;
                return val != null ? val.ToString() : null;
            }
        }

        public static void SetGpoExtensionNames(string guid, string domainDN, string value)
        {
            using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
            {
                entry.Properties["gPCMachineExtensionNames"].Value = value;
                entry.CommitChanges();
            }
        }

        public static void ClearGpoExtensionNames(string guid, string domainDN)
        {
            using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
            {
                entry.Properties["gPCMachineExtensionNames"].Clear();
                entry.CommitChanges();
            }
        }

        public static int GetGpoVersionNumber(string guid, string domainDN)
        {
            using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
            {
                entry.RefreshCache(new string[] { "versionNumber" });
                var val = entry.Properties["versionNumber"].Value;
                return val != null ? (int)val : 0;
            }
        }

        public static void SetGpoVersionNumber(string guid, string domainDN, int value)
        {
            using (var entry = MakeEntry(LdapPath("CN=" + guid + ",CN=Policies,CN=System," + domainDN)))
            {
                entry.Properties["versionNumber"].Value = value;
                entry.CommitChanges();
            }
        }

        // ── Domain admin lookups ─────────────────────────────────────────────

        // Returns sAMAccountName of first enabled Domain Admins member.
        public static string FindFirstActiveDomainAdmin(string domainDN)
        {
            using (var root = MakeEntry(LdapPath(domainDN)))
            using (var searcher = new DirectorySearcher(root))
            {
                searcher.Filter = "(&(objectClass=group)(sAMAccountName=Domain Admins))";
                searcher.PropertiesToLoad.Add("member");
                var groupResult = searcher.FindOne();
                if (groupResult == null) return null;

                foreach (string memberDN in groupResult.Properties["member"])
                {
                    try
                    {
                        using (var userRoot = MakeEntry(LdapPath(memberDN)))
                        using (var userSearcher = new DirectorySearcher(userRoot))
                        {
                            userSearcher.Filter = "(objectClass=user)";
                            userSearcher.SearchScope = SearchScope.Base;
                            userSearcher.PropertiesToLoad.Add("sAMAccountName");
                            userSearcher.PropertiesToLoad.Add("userAccountControl");
                            var userResult = userSearcher.FindOne();
                            if (userResult == null) continue;
                            int uac = (int)userResult.Properties["userAccountControl"][0];
                            bool isEnabled = (uac & 2) == 0;
                            if (!isEnabled) continue;
                            var samVal = userResult.Properties["sAMAccountName"];
                            if (samVal != null && samVal.Count > 0 && samVal[0] != null)
                                return samVal[0].ToString();
                        }
                    }
                    catch { }
                }
            }
            return null;
        }

        // Checks Domain Admins membership for the given username.
        public static bool IsDomainAdmin(string username, string domainDN)
        {
            using (var root = MakeEntry(LdapPath(domainDN)))
            using (var searcher = new DirectorySearcher(root))
            {
                searcher.Filter = "(&(objectClass=group)(sAMAccountName=Domain Admins))";
                searcher.PropertiesToLoad.Add("member");
                var groupResult = searcher.FindOne();
                if (groupResult == null) return false;

                foreach (string memberDN in groupResult.Properties["member"])
                {
                    try
                    {
                        using (var userRoot = MakeEntry(LdapPath(memberDN)))
                        using (var userSearcher = new DirectorySearcher(userRoot))
                        {
                            userSearcher.Filter = "(objectClass=user)";
                            userSearcher.SearchScope = SearchScope.Base;
                            userSearcher.PropertiesToLoad.Add("sAMAccountName");
                            var userResult = userSearcher.FindOne();
                            if (userResult == null) continue;
                            var samVal = userResult.Properties["sAMAccountName"];
                            if (samVal == null || samVal.Count == 0) continue;
                            string sam = samVal[0] != null ? samVal[0].ToString() : null;
                            if (sam != null && sam.Equals(username, StringComparison.OrdinalIgnoreCase))
                                return true;
                        }
                    }
                    catch { }
                }
            }
            return false;
        }

        // Checks if username appears in local Administrators on a remote computer via WMI.
        public static bool IsLocalAdmin(string computer, string username)
        {
            try
            {
                var scope = new ManagementScope(@"\\" + computer + @"\root\cimv2");
                scope.Options.Impersonation = ImpersonationLevel.Impersonate;
                scope.Connect();

                var groupQuery = new ObjectQuery("SELECT * FROM Win32_Group WHERE SID='S-1-5-32-544'");
                using (var groupSearcher = new ManagementObjectSearcher(scope, groupQuery))
                using (var groups = groupSearcher.Get())
                {
                    foreach (ManagementObject grp in groups)
                    {
                        var assocQuery = new RelatedObjectQuery(grp.Path.Path, "Win32_UserAccount");
                        using (var assocSearcher = new ManagementObjectSearcher(scope, assocQuery))
                        using (var users = assocSearcher.Get())
                        {
                            foreach (ManagementObject user in users)
                            {
                                var nameVal = user["Name"];
                                string name = nameVal != null ? nameVal.ToString() : null;
                                if (name != null && name.IndexOf(username, StringComparison.OrdinalIgnoreCase) >= 0)
                                    return true;
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        // ── Link / OU helpers ────────────────────────────────────────────────

        // Returns linked locations (OUs, domain root) for a GPO.
        public static List<string> GetLinkedLocations(string guid, string domainDN)
        {
            var locations = new List<string>();

            try
            {
                using (var domainRoot = MakeEntry(LdapPath(domainDN)))
                {
                    var gpLinkVal = domainRoot.Properties["gPLink"].Value;
                    string gpLink = gpLinkVal != null ? gpLinkVal.ToString() : "";
                    if (gpLink.IndexOf(guid, StringComparison.OrdinalIgnoreCase) >= 0)
                        locations.Add("Domain Root (" + domainDN + ")");
                }
            }
            catch { }

            try
            {
                using (var root = MakeEntry(LdapPath(domainDN)))
                using (var searcher = new DirectorySearcher(root))
                {
                    searcher.Filter = "(&(objectClass=organizationalUnit)(gpLink=*" + guid + "*))";
                    searcher.SearchScope = SearchScope.Subtree;
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    using (var results = searcher.FindAll())
                    {
                        foreach (SearchResult ou in results)
                        {
                            var dnVal = ou.Properties["distinguishedName"];
                            if (dnVal != null && dnVal.Count > 0 && dnVal[0] != null)
                                locations.Add("OU: " + dnVal[0].ToString());
                        }
                    }
                }
            }
            catch { }

            return locations;
        }

        // Returns computer names in a given OU (one level).
        public static List<string> GetComputersInOU(string ouDN)
        {
            var computers = new List<string>();
            try
            {
                using (var root = MakeEntry(LdapPath(ouDN)))
                using (var searcher = new DirectorySearcher(root))
                {
                    searcher.Filter = "(objectClass=computer)";
                    searcher.SearchScope = SearchScope.OneLevel;
                    searcher.PropertiesToLoad.Add("name");
                    using (var results = searcher.FindAll())
                    {
                        foreach (SearchResult r in results)
                        {
                            var nameVal = r.Properties["name"];
                            if (nameVal != null && nameVal.Count > 0 && nameVal[0] != null)
                                computers.Add(nameVal[0].ToString());
                        }
                    }
                }
            }
            catch { }
            return computers;
        }

        private static string EscapeLdap(string value)
        {
            return value
                .Replace("\\", "\\5c")
                .Replace("*",  "\\2a")
                .Replace("(",  "\\28")
                .Replace(")",  "\\29")
                .Replace("\0", "\\00");
        }
    }
}

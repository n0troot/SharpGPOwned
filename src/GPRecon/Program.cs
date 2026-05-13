using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using GPOwned.Shared;

namespace GPRecon
{
    internal static class Program
    {
        static int Main(string[] args)
        {
            Output.EnableAnsi();
            Output.Banner("GPRecon", "GPO Write-Access Reconnaissance  ·  @n0troot");

            if (args.Length == 0 || HasFlag(args, "--help", "-h", "-help"))
            {
                ShowHelp();
                return 0;
            }

            bool all        = HasFlag(args, "--all",        "-all");
            bool full       = HasFlag(args, "--full",       "-full");
            bool vulnerable = HasFlag(args, "--vulnerable", "-vulnerable");
            string gpo      = GetArg(args,  "--gpo",        "-gpo");

            if (!all && string.IsNullOrEmpty(gpo))
            {
                Output.Red("Specify --all to check all GPOs or --gpo <name|GUID> for a specific one.");
                ShowHelp();
                return 1;
            }

            string domain, domainDN;
            try
            {
                AdHelper.GetDomainInfo(out domain, out domainDN);
            }
            catch (Exception ex)
            {
                Output.Red("Failed to contact domain controller: " + ex.Message);
                return 1;
            }

            Output.Gray("Domain : " + domain);
            Output.Gray("Base DN: " + domainDN);

            if (all)
                CheckAll(domain, domainDN, full, vulnerable);
            else
                CheckSingle(gpo, domain, domainDN, full);

            return 0;
        }

        static void CheckAll(string domain, string domainDN, bool full, bool vulnerable)
        {
            string sysvolPolicies = @"\\" + domain + @"\SYSVOL\" + domain + @"\Policies";
            string[] dirs;
            try
            {
                dirs = Directory.GetDirectories(sysvolPolicies);
            }
            catch (Exception ex)
            {
                Output.Red("Cannot enumerate SYSVOL: " + ex.Message);
                return;
            }

            int total = 0;
            foreach (string dir in dirs)
                if (Path.GetFileName(dir).StartsWith("{")) total++;

            Output.SectionHeader("GPO Scan" + (vulnerable ? "  [ writable only ]" : ""));
            Output.Gray("SYSVOL : " + sysvolPolicies);
            Output.Gray("Count  : " + total + " GPOs");
            Console.WriteLine();

            var writable = new List<string>();

            foreach (string dir in dirs)
            {
                string guid = Path.GetFileName(dir);
                if (!guid.StartsWith("{")) continue;

                string displayName = AdHelper.ResolveGpoName(guid, domainDN);
                bool isWritable    = AdHelper.CheckGpoWriteAccess(guid, domainDN);

                if (isWritable) writable.Add(guid);

                if (isWritable || !vulnerable)
                    Output.GpoResult(displayName, guid, isWritable);
            }

            Output.Summary(writable.Count, total);

            if (writable.Count == 0) return;

            Output.SectionHeader("Linked Locations");
            foreach (string guid in writable)
            {
                string displayName = AdHelper.ResolveGpoName(guid, domainDN);
                PrintLinkedLocations(guid, displayName, domainDN, full);
            }
            Console.WriteLine();
        }

        static void CheckSingle(string gpoIdentifier, string domain, string domainDN, bool full)
        {
            string guid = gpoIdentifier;

            if (!IsGuid(gpoIdentifier))
            {
                guid = AdHelper.ResolveGpoGuid(gpoIdentifier, domainDN);
                if (string.IsNullOrEmpty(guid))
                {
                    Output.Red("Unable to find GPO: " + gpoIdentifier);
                    return;
                }
            }

            string displayName = AdHelper.ResolveGpoName(guid, domainDN);
            bool isWritable    = AdHelper.CheckGpoWriteAccess(guid, domainDN);

            Output.SectionHeader("GPO Status");
            Output.GpoResult(displayName, guid, isWritable);

            Output.SectionHeader("Linked Locations");
            PrintLinkedLocations(guid, displayName, domainDN, full);
            Console.WriteLine();
        }

        static void PrintLinkedLocations(string guid, string displayName, string domainDN, bool full)
        {
            List<string> locations = AdHelper.GetLinkedLocations(guid, domainDN);
            Output.LinkedItem(displayName, guid);

            if (locations.Count == 0)
            {
                Output.LinkedLocation("(not linked to any OU or domain root)");
                return;
            }

            foreach (string loc in locations)
            {
                Output.LinkedLocation(loc);
                if (full && loc.StartsWith("OU:", StringComparison.OrdinalIgnoreCase))
                {
                    string ouDN = loc.Substring(4).Trim();
                    List<string> computers = AdHelper.GetComputersInOU(ouDN);
                    if (computers.Count > 0)
                        Output.ComputerList(computers);
                    else
                        Console.WriteLine("         (no computers found in this OU)");
                }
            }
        }

        static bool IsGuid(string s)
        {
            string clean = s.Trim('{', '}');
            return Regex.IsMatch(clean,
                @"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$");
        }

        static string GetArg(string[] args, params string[] flags)
        {
            for (int i = 0; i < args.Length - 1; i++)
                foreach (string f in flags)
                    if (args[i].Equals(f, StringComparison.OrdinalIgnoreCase))
                        return args[i + 1];
            return null;
        }

        static bool HasFlag(string[] args, params string[] flags)
        {
            foreach (string a in args)
                foreach (string f in flags)
                    if (a.Equals(f, StringComparison.OrdinalIgnoreCase))
                        return true;
            return false;
        }

        static void ShowHelp()
        {
            Console.WriteLine(
                "\n  OPTIONS:\n" +
                "    --all                    Scan all GPOs in the domain\n" +
                "    --gpo  <name|GUID>       Check a specific GPO\n" +
                "    --vulnerable             Only show writable GPOs  (use with --all)\n" +
                "    --full                   Also list computers in linked OUs\n" +
                "    --help / -h              Show this help\n" +
                "\n  EXAMPLES:\n" +
                "    GPRecon.exe --all\n" +
                "    GPRecon.exe --all --vulnerable\n" +
                "    GPRecon.exe --all --full\n" +
                "    GPRecon.exe --gpo \"Default Domain Policy\"\n" +
                "    GPRecon.exe --gpo {31B2F340-016D-11D2-945F-00C04FB984F9} --full\n"
            );
        }
    }
}

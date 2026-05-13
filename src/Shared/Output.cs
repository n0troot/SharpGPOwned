using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace GPOwned.Shared
{
    public static class Output
    {
        private const string Rst  = "\x1b[0m";
        private const string Bold = "\x1b[1m";
        private const string GRN  = "\x1b[92m";
        private const string RED  = "\x1b[91m";
        private const string YEL  = "\x1b[93m";
        private const string CYN  = "\x1b[96m";
        private const string WHT  = "\x1b[97m";
        private const string DIM  = "\x1b[90m";

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetConsoleMode(IntPtr h, out uint mode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleMode(IntPtr h, uint mode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int n);

        public static void EnableAnsi()
        {
            try
            {
                Console.OutputEncoding = Encoding.UTF8;
                IntPtr h = GetStdHandle(-11);
                uint m;
                if (GetConsoleMode(h, out m))
                    SetConsoleMode(h, m | 0x0004);
            }
            catch { }
        }

        public static void Banner(string tool, string subtitle)
        {
            string body = "  " + tool + "  ·  " + subtitle + "  ";
            int width   = Math.Max(body.Length, 60);
            Console.WriteLine();
            Console.WriteLine(CYN + Bold + "  ┌" + new string('─', width) + "┐" + Rst);
            Console.WriteLine(CYN + Bold + "  │" + body.PadRight(width) + "│" + Rst);
            Console.WriteLine(CYN + Bold + "  └" + new string('─', width) + "┘" + Rst);
            Console.WriteLine();
        }

        public static void SectionHeader(string title)
        {
            Console.WriteLine();
            string line = "─── " + title + " ";
            Console.WriteLine(DIM + "  " + line + new string('─', Math.Max(0, 64 - line.Length)) + Rst);
        }

        public static void Divider()
        {
            Console.WriteLine(DIM + "  " + new string('─', 64) + Rst);
        }

        public static void Green(string msg) { Console.WriteLine(GRN + "  [+] " + Rst + msg); }
        public static void Red(string msg)   { Console.WriteLine(RED + "  [-] " + Rst + msg); }
        public static void Gray(string msg)  { Console.WriteLine(DIM + "  [*] " + Rst + msg); }
        public static void Warn(string msg)  { Console.WriteLine(YEL + "  [!] " + Rst + msg); }
        public static void Step(string msg)  { Console.WriteLine(WHT + "  [>] " + Rst + msg); }

        public static void GpoResult(string name, string guid, bool writable)
        {
            string tag = writable
                ? GRN + Bold + " WRITABLE " + Rst
                : DIM         + " read-only" + Rst;
            string n = name.Length > 38 ? name.Substring(0, 35) + "..." : name.PadRight(38);
            Console.WriteLine("  " + tag + "  " + WHT + n + Rst + "  " + DIM + guid + Rst);
        }

        public static void LinkedItem(string name, string guid)
        {
            Console.WriteLine();
            Console.WriteLine("  " + CYN + "► " + Rst + WHT + Bold + name + Rst
                              + "  " + DIM + guid + Rst);
        }

        public static void LinkedLocation(string loc)
        {
            Console.WriteLine(DIM + "      └─ " + Rst + loc);
        }

        public static void ComputerList(List<string> computers)
        {
            if (computers == null || computers.Count == 0) return;
            Console.WriteLine(DIM + "         ├ " + Rst + "Computers: "
                              + WHT + string.Join(", ", computers.ToArray()) + Rst);
        }

        public static void Summary(int found, int total)
        {
            Console.WriteLine();
            if (found == 0)
                Console.WriteLine(RED + "  [-] " + Rst
                                  + "No writable GPOs found out of "
                                  + WHT + total + Rst + " scanned.");
            else
                Console.WriteLine(GRN + "  [+] " + Bold + found + Rst
                                  + GRN + " writable GPO(s) found out of "
                                  + WHT + total + Rst + " scanned.");
            Divider();
        }

        public static void Progress(int current, int total, string label)
        {
            int barW   = 32;
            int filled = total > 0 ? (int)((double)current / total * barW) : 0;
            string bar = new string('█', filled) + new string('░', barW - filled);
            string pct = ((double)current / total * 100).ToString("F0").PadLeft(3) + "%";
            string eta = current + "/" + total + " min";
            Console.Write(
                "\r  " + CYN + "[>]" + Rst
                + " [" + CYN + bar + Rst + "]  "
                + WHT + pct + Rst + "  "
                + DIM + eta + Rst + "  "
                + label + "    ");
        }

        public static void EndProgress() { Console.WriteLine(); }
    }

    public sealed class TeeWriter : TextWriter
    {
        private readonly TextWriter _con;
        private readonly StreamWriter _file;

        public TeeWriter(string path)
        {
            _con  = Console.Out;
            _file = new StreamWriter(path, false);
            _file.AutoFlush = true;
            Console.SetOut(this);
        }

        public override Encoding Encoding { get { return _con.Encoding; } }

        public override void Write(char value)       { _con.Write(value);     _file.Write(value); }
        public override void Write(string value)     { _con.Write(value);     _file.Write(value); }
        public override void WriteLine(string value) { _con.WriteLine(value); _file.WriteLine(value); }
        public override void WriteLine()             { _con.WriteLine();      _file.WriteLine(); }

        public void Stop()
        {
            Console.SetOut(_con);
            _file.Flush();
            _file.Close();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _file != null) { _file.Dispose(); }
            base.Dispose(disposing);
        }
    }
}

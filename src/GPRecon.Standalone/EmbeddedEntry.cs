using System;
using System.Reflection;
using System.Runtime.CompilerServices;

// Hooks AssemblyResolve before any GPOwned.Shared types are JIT-resolved,
// then invokes the real Program.Main via reflection.
internal class EmbeddedEntry
{
    static int Main(string[] args)
    {
        AppDomain.CurrentDomain.AssemblyResolve += ResolveEmbedded;
        return Run(args);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static int Run(string[] args)
    {
        return (int)typeof(GPRecon.Program)
            .GetMethod("Main",
                BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public,
                null, new[] { typeof(string[]) }, null)
            .Invoke(null, new object[] { args });
    }

    static Assembly ResolveEmbedded(object sender, ResolveEventArgs e)
    {
        string name = new AssemblyName(e.Name).Name;
        using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name + ".dll"))
        {
            if (s == null) return null;
            var buf = new byte[s.Length];
            s.Read(buf, 0, buf.Length);
            return Assembly.Load(buf);
        }
    }
}

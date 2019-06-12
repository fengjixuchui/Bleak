using System;
using System.IO;
using Bleak.PortableExecutable;

namespace Bleak.RemoteProcess.Objects
{
    internal class Module
    {
        internal readonly IntPtr BaseAddress;

        internal readonly string FilePath;

        internal readonly string Name;

        internal readonly Lazy<PeParser> PeParser;
        
        internal Module(IntPtr baseAddress, string filePath, string name)
        {
            BaseAddress = baseAddress;

            FilePath = filePath;

            Name = name;
            
            PeParser = new Lazy<PeParser>(() => new PeParser(File.ReadAllBytes(filePath)));
        }
    }
}
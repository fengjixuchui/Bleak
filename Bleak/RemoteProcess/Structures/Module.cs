using System;
using System.IO;
using Bleak.PortableExecutable;

namespace Bleak.RemoteProcess.Structures
{
    internal sealed class Module
    {
        internal readonly IntPtr BaseAddress;

        internal readonly string Name;

        internal readonly Lazy<PeImage> PeImage;

        internal Module(IntPtr baseAddress, string filePath, string name)
        {
            BaseAddress = baseAddress;

            Name = name;

            PeImage = new Lazy<PeImage>(() => new PeImage(File.ReadAllBytes(filePath)));
        }
    }
}
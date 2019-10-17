using System;
using System.Diagnostics;
using System.IO;
using System.Reflection.PortableExecutable;
using Bleak.Native.Enumerations;
using Bleak.PortableExecutable;
using Bleak.ProgramDatabase;
using Bleak.RemoteProcess;

namespace Bleak.Injection
{
    internal abstract class InjectionBase : IDisposable
    {
        internal IntPtr DllBaseAddress;

        protected readonly byte[] DllBytes;

        protected readonly string DllPath;

        protected readonly InjectionFlags InjectionFlags;

        protected readonly Lazy<PdbFile> PdbFile;

        protected readonly PeImage PeImage;

        protected readonly ProcessManager ProcessManager;

        protected InjectionBase(byte[] dllBytes, Process process, InjectionMethod injectionMethod, InjectionFlags injectionFlags)
        {
            DllBytes = dllBytes;

            InjectionFlags = injectionFlags;

            PdbFile = new Lazy<PdbFile>(() => new PdbFile(ProcessManager.Modules.Find(module => module.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)), ProcessManager.IsWow64));

            PeImage = new PeImage(dllBytes);

            ProcessManager = new ProcessManager(process, injectionMethod);

            ValidateArchitecture();
        }

        protected InjectionBase(string dllPath, Process process, InjectionMethod injectionMethod, InjectionFlags injectionFlags)
        {
            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = dllPath;

            InjectionFlags = injectionFlags;

            PdbFile = new Lazy<PdbFile>(() => new PdbFile(ProcessManager.Modules.Find(module => module.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)), ProcessManager.IsWow64));

            PeImage = new PeImage(DllBytes);

            ProcessManager = new ProcessManager(process, injectionMethod);

            ValidateArchitecture();
        }

        public void Dispose()
        {
            ProcessManager.Dispose();
        }

        internal void RandomiseDllHeaders()
        {
            // Write over the header region of the DLL with random bytes

            var randomBuffer = new byte[PeImage.Headers.PEHeader.SizeOfHeaders];

            new Random().NextBytes(randomBuffer);

            ProcessManager.Memory.ProtectBlock(DllBaseAddress, randomBuffer.Length, ProtectionType.ReadWrite);

            ProcessManager.Memory.WriteBlock(DllBaseAddress, randomBuffer);

            ProcessManager.Memory.ProtectBlock(DllBaseAddress, randomBuffer.Length, ProtectionType.ReadOnly);
        }

        internal abstract void Eject();

        internal abstract void Inject();

        private void ValidateArchitecture()
        {
            // Ensure the architecture of the process matches the architecture of the DLL

            if (ProcessManager.IsWow64 != (PeImage.Headers.PEHeader.Magic == PEMagic.PE32))
            {
                throw new ApplicationException("The architecture of the remote process did not match the architecture of the DLL");
            }

            // Ensure that x64 injection is not being attempted from an x86 build

            if (!Environment.Is64BitProcess && !ProcessManager.IsWow64)
            {
                throw new ApplicationException("x64 injection is not supported when compiled under x86");
            }
        }
    }
}
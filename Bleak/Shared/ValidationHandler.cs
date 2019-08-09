using System;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Bleak.Injection.Objects;

namespace Bleak.Shared
{
    internal static class ValidationHandler
    {
        internal static void ValidateDllArchitecture(InjectionWrapper injectionWrapper)
        {
            // Ensure the architecture of the remote process matches the architecture of the DLL

            if (injectionWrapper.Process.IsWow64 != (injectionWrapper.PeImage.PeHeaders.PEHeader.Magic == PEMagic.PE32))
            {
                throw new ApplicationException("The architecture of the remote process did not match the architecture of the DLL");
            }

            // Ensure that x64 injection is not being attempted from an x86 build

            if (!Environment.Is64BitProcess && !injectionWrapper.Process.IsWow64)
            {
                throw new ApplicationException("x64 injection is not supported when compiled under x86");
            }
        }
        
        internal static void ValidateOperatingSystem()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                throw new PlatformNotSupportedException("This library is intended for Windows use only");
            }

            if (!Environment.Is64BitOperatingSystem)
            {
                throw new PlatformNotSupportedException("This library is intended for 64 bit Windows use only");
            }
        }   
    }
}
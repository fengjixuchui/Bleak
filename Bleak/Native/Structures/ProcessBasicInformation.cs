using System;
using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessBasicInformation
    {
        private readonly IntPtr ExitStatus;

        internal readonly IntPtr PebBaseAddress;

        private readonly IntPtr AffinityMask;

        private readonly IntPtr BasePriority;

        private readonly IntPtr UniqueProcessId;

        private readonly IntPtr InheritedFromUniqueProcessId;
    }
}
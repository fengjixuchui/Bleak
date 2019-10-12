using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct ImageBaseRelocation
    {
        internal readonly int VirtualAddress;

        internal readonly int SizeOfBlock;
    }
}
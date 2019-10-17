using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal readonly struct ImageDebugDirectory
    {
        [FieldOffset(0x14)]
        internal readonly int AddressOfRawData;
    }
}
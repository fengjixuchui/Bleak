using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct ApiSetValueEntry
    {
        [FieldOffset(0x0C)]
        internal readonly int ValueOffset;

        [FieldOffset(0x10)]
        internal readonly int ValueCount;
    }
}
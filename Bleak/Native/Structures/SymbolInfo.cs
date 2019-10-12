using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct SymbolInfo
    {
        [FieldOffset(0x38)]
        internal readonly long Address;

        [FieldOffset(0x4C)]
        internal readonly int NameLen;

        [FieldOffset(0x54)]
        internal byte Name;
    }
}
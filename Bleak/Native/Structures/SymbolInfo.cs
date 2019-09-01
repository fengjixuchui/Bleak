using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 84)]
    internal struct SymbolInfo
    {
        [FieldOffset(0x38)]
        internal readonly long Address;
    }
}
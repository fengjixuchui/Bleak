using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 14)]
    internal struct SymbolData
    {
        [FieldOffset(0x00)]
        internal readonly short Length;

        [FieldOffset(0x02)]
        internal readonly short Magic;
        
        [FieldOffset(0x08)]
        internal readonly int Offset;

        [FieldOffset(0x0C)]
        internal readonly short Section;
    }
}
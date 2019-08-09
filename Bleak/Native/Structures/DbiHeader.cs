using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct DbiHeader
    {
        [FieldOffset(0x14)]
        internal readonly short SymbolStreamIndex;
    }
}
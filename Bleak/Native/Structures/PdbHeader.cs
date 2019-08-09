using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct PdbHeader
    {
        [FieldOffset(0x20)]
        internal readonly int PageSize;

        [FieldOffset(0x34)]
        internal readonly int RootStreamPageNumberListNumber;
    }
}
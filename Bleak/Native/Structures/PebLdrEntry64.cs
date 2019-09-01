using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct PebLdrData64
    {
        [FieldOffset(0x20)]
        internal readonly ListEntry64 InMemoryOrderModuleList;
    }
}
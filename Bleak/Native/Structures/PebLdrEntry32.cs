using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct PebLdrData32
    {
        [FieldOffset(0x14)]
        internal readonly ListEntry32 InMemoryOrderModuleList;
    }
}
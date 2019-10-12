using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ListEntry<TPointer> where TPointer : struct
    {
        internal TPointer Flink;

        internal TPointer Blink;
    }
}
using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ListEntry32
    {
        internal int Flink;

        internal int Blink;
    }
}
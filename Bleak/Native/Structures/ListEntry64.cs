using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ListEntry64
    {
        internal long Flink;
        
        internal long Blink;
    }
}
using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct ImageTlsDirectory32
    {
        [FieldOffset(0x0C)]
        internal readonly int AddressOfCallbacks;
    }
}
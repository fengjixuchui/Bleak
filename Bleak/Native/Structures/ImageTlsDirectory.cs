using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct ImageTlsDirectory<TPointer> where TPointer : struct
    {
        private readonly TPointer StartAddressOfRawData;

        private readonly TPointer EndAddressOfRawData;

        private readonly TPointer AddressOfIndex;

        internal readonly TPointer AddressOfCallbacks;
    }
}
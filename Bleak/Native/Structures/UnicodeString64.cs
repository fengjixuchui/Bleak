using System;
using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct UnicodeString64
    {
        internal readonly short Length;

        private readonly short MaximumLength;

        internal readonly long Buffer;

        internal UnicodeString64(string @string, IntPtr buffer)
        {
            Length = (short) (@string.Length * 2);

            MaximumLength = (short) (Length + 2);

            Buffer = (long) buffer;
        }
    }
}
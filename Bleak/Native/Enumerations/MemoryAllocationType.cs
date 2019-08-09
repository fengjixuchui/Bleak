using System;

namespace Bleak.Native.Enumerations
{
    [Flags]
    internal enum MemoryAllocationType
    {
        Commit = 0x1000,
        Reserve = 0x2000
    }
}
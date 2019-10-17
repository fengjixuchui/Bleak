using System;

namespace Bleak.Native.Enumerations
{
    [Flags]
    internal enum ThreadCreationFlags
    {
        CreateSuspended = 0x01,
        HideFromDebugger = 0x04
    }
}
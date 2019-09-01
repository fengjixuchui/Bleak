using System;

namespace Bleak.Native
{
    internal static class Prototypes
    {
        internal delegate bool EnumerateSymbolsCallback(IntPtr symbolInfo, int symbolSize, IntPtr userContext);
    }
}
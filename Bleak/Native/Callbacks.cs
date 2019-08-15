using System;

namespace Bleak.Native
{
    internal static class Callbacks
    {
        internal delegate bool EnumerateSymbolsCallback(IntPtr symbolInfo, int symbolSize, IntPtr userContext);
    }
}
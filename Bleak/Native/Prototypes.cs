using System;
using Bleak.Native.Structures;

namespace Bleak.Native
{
    internal static class Prototypes
    {
        internal delegate bool EnumerateSymbolsCallback(ref SymbolInfo symbolInfo, int symbolSize, IntPtr userContext);
    }
}
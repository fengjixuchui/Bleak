namespace Bleak.Native
{
    internal static class Constants
    {
        internal const int DllProcessAttach = 0x01;
        
        internal const int DllProcessDetach = 0x00;
        
        internal const uint OrdinalFlag32 = 0x80000000;
        
        internal const ulong OrdinalFlag64 = 0x8000000000000000;
        
        internal const int SymbolMagic = 0x110E;
        
        internal const int ThreadAllAccess = 0x1FFFFF;
    }
}
using static Bleak.Native.Structures;

namespace Bleak.RemoteProcess.Objects
{
    internal class PebEntry
    {
        internal readonly object LoaderEntry;
        
        internal PebEntry(LdrDataTableEntry32 loaderEntry)
        {
            LoaderEntry = loaderEntry;
        }
        
        internal PebEntry(LdrDataTableEntry64 loaderEntry)
        {
            LoaderEntry = loaderEntry;
        }
    }
}
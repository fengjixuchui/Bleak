using System;
using System.Runtime.InteropServices;
using static Bleak.Native.Enumerations;

namespace Bleak.Native
{
    internal static class Structures
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct ApiSetNamespace
        {
            private readonly uint Version;

            private readonly uint Size;

            private readonly uint Flags;

            internal readonly uint Count;

            internal readonly uint EntryOffset;

            private readonly uint HashOffset;
            private readonly uint HashFactor;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ApiSetNamespaceEntry
        {
            private readonly uint Flags;

            internal readonly uint NameOffset;
            internal readonly uint NameLength;

            private readonly uint HashedLength;

            internal readonly uint ValueOffset;

            private readonly uint ValueCount;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ApiSetValueEntry
        {
            private readonly uint Flags;

            private readonly uint NameOffset;
            private readonly uint NameLength;

            internal readonly uint ValueOffset;
            internal readonly uint ValueCount;
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct Context
        {
            private readonly ulong P1Home;
            private readonly ulong P2Home;
            private readonly ulong P3Home;
            private readonly ulong P4Home;
            private readonly ulong P5Home;
            private readonly ulong P6Home;

            internal ContextFlags ContextFlags;

            private readonly uint MxCsr;

            private readonly ushort SegCs;
            private readonly ushort SegDs;
            private readonly ushort SegEs;
            private readonly ushort SegFs;
            private readonly ushort SegGs;
            private readonly ushort SegSs;

            private readonly uint EFlags;

            private readonly ulong Dr0;
            private readonly ulong Dr1;
            private readonly ulong Dr2;
            private readonly ulong Dr3;
            private readonly ulong Dr6;
            private readonly ulong Dr7;

            private readonly ulong Rax;
            private readonly ulong Rcx;
            private readonly ulong Rdx;
            private readonly ulong Rbx;

            internal ulong Rsp;

            private readonly ulong Rbp;
            private readonly ulong Rsi;
            private readonly ulong Rdi;
            private readonly ulong R8;
            private readonly ulong R9;
            private readonly ulong R10;
            private readonly ulong R11;
            private readonly ulong R12;
            private readonly ulong R13;
            private readonly ulong R14;
            private readonly ulong R15;

            internal ulong Rip;

            private readonly SaveFormat DummyUnionName;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            private readonly M128A[] VectorRegister;

            private readonly ulong VectorControl;
            private readonly ulong DebugControl;

            private readonly ulong LastBranchToRip;
            private readonly ulong LastBranchFromRip;
            private readonly ulong LastExceptionToRip;
            private readonly ulong LastExceptionFromRip;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct DbiHeader
        {
            private readonly uint Signature;

            private readonly uint Version;

            private readonly uint Age;

            private readonly ushort GlobalStreamIndex;

            private readonly ushort PdbBuildNumber;

            private readonly ushort PublicStreamIndex;

            private readonly ushort DllVersion;

            internal readonly ushort SymbolStreamIndex;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageBaseRelocation
        {
            internal readonly uint VirtualAddress;

            internal readonly uint SizeOfBlock;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageExportDirectory
        {
            private readonly uint Characteristics;

            private readonly uint TimeDateStamp;

            private readonly ushort MajorVersion;
            private readonly ushort MinorVersion;

            private readonly uint Name;

            internal readonly uint Base;

            internal readonly uint NumberOfFunctions;
            internal readonly uint NumberOfNames;

            internal readonly uint AddressOfFunctions;
            internal readonly uint AddressOfNames;
            internal readonly uint AddressOfNameOrdinals;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageImportDescriptor
        {
            internal readonly uint OriginalFirstThunk;

            private readonly uint TimeDateStamp;

            private readonly uint ForwarderChain;

            internal readonly uint Name;

            internal readonly uint FirstThunk;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageRuntimeFunctionEntry
        {
            private readonly uint BeginAddress;

            private readonly uint EndAddress;

            private readonly uint UnwindInfoAddress;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageTlsDirectory32
        {
            private readonly uint StartAddressOfRawData;
            private readonly uint EndAddressOfRawData;

            private readonly uint AddressOfIndex;

            internal readonly uint AddressOfCallbacks;

            private readonly uint SizeOfZeroFill;

            private readonly uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageTlsDirectory64
        {
            private readonly ulong StartAddressOfRawData;
            private readonly ulong EndAddressOfRawData;

            private readonly ulong AddressOfIndex;

            internal readonly ulong AddressOfCallbacks;

            private readonly uint SizeOfZeroFill;

            private readonly uint Characteristics;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct LdrDataTableEntry32
        {
            internal readonly ListEntry32 InLoadOrderLinks;
            internal readonly ListEntry32 InMemoryOrderLinks;
            internal readonly ListEntry32 InInitializationOrderLinks;

            internal readonly uint DllBase;

            private readonly uint EntryPoint;

            private readonly uint SizeOfImage;

            internal UnicodeString32 FullDllName;
            internal UnicodeString32 BaseDllName;

            private readonly uint Flags;

            private readonly ushort ObsoleteLoadCount;

            private readonly ushort TlsIndex;

            internal readonly ListEntry32 HashLinks;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct LdrDataTableEntry64
        {
            internal readonly ListEntry64 InLoadOrderLinks;
            internal readonly ListEntry64 InMemoryOrderLinks;
            internal readonly ListEntry64 InInitializationOrderLinks;

            internal readonly ulong DllBase;

            private readonly ulong EntryPoint;

            private readonly ulong SizeOfImage;

            internal UnicodeString64 FullDllName;
            internal UnicodeString64 BaseDllName;

            private readonly uint Flags;

            private readonly ushort ObsoleteLoadCount;

            private readonly ushort TlsIndex;

            internal readonly ListEntry64 HashLinks;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ListEntry32
        {
            internal uint Flink;
            internal uint Blink;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ListEntry64
        {
            internal ulong Flink;
            internal ulong Blink;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct M128A
        {
            private readonly ulong High;
            private readonly ulong Low;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct PdbHeader
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            private readonly char[] Signature;

            internal readonly uint PageSize;

            private readonly uint AllocationTablePointer;

            private readonly uint FilePageCount;

            private readonly uint RootStreamSize;

            private readonly uint Reserved;

            internal readonly uint RootStreamPageNumberListNumber;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct Peb32
        {
            private readonly byte InheritedAddressSpace;

            private readonly byte ReadImageFileExecOptions;

            private readonly byte BeingDebugged;

            private readonly byte BitField;

            private readonly uint Mutant;

            private readonly uint ImageBaseAddress;

            internal readonly uint Ldr;

            private readonly uint ProcessParameters;

            private readonly uint SubSystemData;

            private readonly uint ProcessHeap;

            private readonly uint FastPebLock;

            private readonly uint AltThunkSListPtr;

            private readonly uint IFEOKey;

            private readonly uint CrossProcessFlags;

            private readonly uint KernelCallbackTable;

            private readonly uint SystemReserved;

            private readonly uint AtlThunkSListPtr32;

            internal readonly uint ApiSetMap;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct Peb64
        {
            private readonly byte InheritedAddressSpace;

            private readonly byte ReadImageFileExecOptions;

            private readonly byte BeingDebugged;

            private readonly byte BitField;

            private readonly ulong Mutant;

            private readonly ulong ImageBaseAddress;

            internal readonly ulong Ldr;

            private readonly ulong ProcessParameters;

            private readonly ulong SubSystemData;

            private readonly ulong ProcessHeap;

            private readonly ulong FastPebLock;

            private readonly ulong AltThunkSListPtr;

            private readonly ulong IFEOKey;

            private readonly uint CrossProcessFlags;

            private readonly ulong KernelCallbackTable;

            private readonly uint SystemReserved;

            private readonly uint AtlThunkSListPtr32;

            internal readonly ulong ApiSetMap;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct PebLdrData32
        {
            private readonly uint Length;

            private readonly byte Initialized;

            private readonly uint SsHandle;

            internal readonly ListEntry32 InLoadOrderModuleList;

            private readonly ListEntry32 InMemoryOrderModuleList;
            private readonly ListEntry32 InInitOrderModuleList;

            private readonly uint EntryInProgress;

            private readonly byte ShutdownInProgress;
            private readonly uint ShutdownThreadId;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct PebLdrData64
        {
            private readonly uint Length;

            private readonly byte Initialized;

            private readonly ulong SsHandle;

            internal readonly ListEntry64 InLoadOrderModuleList;

            private readonly ListEntry64 InMemoryOrderModuleList;
            private readonly ListEntry64 InInitOrderModuleList;

            private readonly ulong EntryInProgress;

            private readonly byte ShutdownInProgress;
            private readonly ulong ShutdownThreadId;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInformation
        {
            private readonly IntPtr ExitStatus;

            internal readonly IntPtr PebBaseAddress;

            private readonly IntPtr AffinityMask;

            private readonly IntPtr BasePriority;

            private readonly IntPtr UniqueProcessId;
            private readonly IntPtr InheritedFromUniqueProcessId;
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct SaveFormat
        {
            private readonly ushort ControlWord;
            private readonly ushort StatusWord;
            private readonly byte TagWord;

            private readonly byte Reserved;

            private readonly ushort ErrorOpcode;
            private readonly uint ErrorOffset;
            private readonly ushort ErrorSelector;

            private readonly ushort Reserved2;

            private readonly uint DataOffset;
            private readonly ushort DataSelector;

            private readonly ushort Reserved3;

            private readonly uint MxCsr;
            private readonly uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            private readonly M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            private readonly M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            private readonly byte[] Reserved4;
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct SymbolData
        {
            internal readonly ushort Length;

            internal readonly ushort Magic;

            private readonly uint Flags;

            internal readonly uint Offset;

            internal readonly ushort Section;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct UnicodeString32
        {
            internal readonly ushort Length;
            internal readonly ushort MaximumLength;

            internal uint Buffer;

            internal UnicodeString32(string @string)
            {
                Length = (ushort) (@string.Length * 2);

                MaximumLength = (ushort) (Length + 2);

                Buffer = 0;
            }
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct UnicodeString64
        {
            internal readonly ushort Length;
            internal readonly ushort MaximumLength;

            internal ulong Buffer;

            internal UnicodeString64(string @string)
            {
                Length = (ushort) (@string.Length * 2);

                MaximumLength = (ushort) (Length + 2);

                Buffer = 0;
            }
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct Wow64Context
        {
            internal ContextFlags ContextFlags;

            private readonly uint Dr0;
            private readonly uint Dr1;
            private readonly uint Dr2;
            private readonly uint Dr3;
            private readonly uint Dr6;
            private readonly uint Dr7;

            private readonly Wow64FloatingSaveArea FloatingSave;

            private readonly uint SegGs;
            private readonly uint SegFs;
            private readonly uint SegEs;
            private readonly uint SegDs;

            private readonly uint Edi;
            private readonly uint Esi;
            private readonly uint Ebx;
            private readonly uint Edx;
            private readonly uint Ecx;
            private readonly uint Eax;

            private readonly uint Ebp;

            internal uint Eip;

            private readonly uint SegCs;

            private readonly uint EFlags;

            internal uint Esp;

            private readonly uint SegSs;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            private readonly byte[] ExtendedRegisters;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct Wow64FloatingSaveArea
        {
            private readonly uint ControlWord;
            private readonly uint StatusWord;
            private readonly uint TagWord;

            private readonly uint ErrorOffset;
            private readonly uint ErrorSelector;

            private readonly uint DataOffset;
            private readonly uint DataSelector;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            private readonly byte[] RegisterArea;

            private readonly uint Cr0NpxState;
        }
    }
}
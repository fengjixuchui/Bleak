using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.RemoteProcess.Memory;
using Bleak.Shared.Exceptions;
using Microsoft.Win32.SafeHandles;

namespace Bleak.RemoteProcess.Peb
{
    internal class ManagedPeb
    {
        internal readonly IntPtr ApiSetMapAddress;
        
        private readonly bool _isWow64;

        private readonly IntPtr _loaderAddress;
        
        private readonly MemoryManager _memoryManager;

        internal ManagedPeb(bool isWow64, MemoryManager memoryManager, SafeProcessHandle processHandle)
        {
            _isWow64 = isWow64;
            
            _memoryManager = memoryManager;

            var (item1, item2) = ReadPeb(processHandle);

            ApiSetMapAddress = item1;

            _loaderAddress = item2;
        }

        internal Dictionary<IntPtr, LdrDataTableEntry64> GetPebEntries()
        {
            var entries = new Dictionary<IntPtr, LdrDataTableEntry64>();
            
            // Read the loader data of the PEB
            
            var pebLoaderData = _memoryManager.ReadVirtualMemory<PebLdrData64>(_loaderAddress);
            
            var currentEntryAddress = pebLoaderData.InMemoryOrderModuleList.Flink;

            var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry64>("InMemoryOrderLinks");
            
            while (true)
            {
                // Get the current entry of the InMemoryOrder linked list

                var entryAddress = currentEntryAddress - (int) inMemoryOrderLinksOffset;
                
                var entry = _memoryManager.ReadVirtualMemory<LdrDataTableEntry64>((IntPtr) entryAddress);

                entries.Add((IntPtr) entryAddress, entry);
                
                if (currentEntryAddress == pebLoaderData.InMemoryOrderModuleList.Blink)
                {
                    break;
                }
                
                // Get the address of the next entry in the InMemoryOrder linked list
                
                currentEntryAddress = entry.InMemoryOrderLinks.Flink;
            }

            return entries;
        }
        
        internal Dictionary<IntPtr, LdrDataTableEntry32> GetWow64PebEntries()
        {
            var entries = new Dictionary<IntPtr, LdrDataTableEntry32>();
            
            // Read the loader data of the WOW64 PEB
            
            var pebLoaderData = _memoryManager.ReadVirtualMemory<PebLdrData32>(_loaderAddress);
            
            var currentEntryAddress = pebLoaderData.InMemoryOrderModuleList.Flink;

            var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry32>("InMemoryOrderLinks");
            
            while (true)
            {
                // Get the current entry of the InMemoryOrder linked list
                
                var entryAddress = currentEntryAddress - (int) inMemoryOrderLinksOffset;
                
                var entry = _memoryManager.ReadVirtualMemory<LdrDataTableEntry32>((IntPtr) entryAddress);
                
                entries.Add((IntPtr) entryAddress, entry);
                
                if (currentEntryAddress == pebLoaderData.InMemoryOrderModuleList.Blink)
                {
                    break;
                }
                
                // Get the address of the next entry in the InMemoryOrder linked list
                
                currentEntryAddress = entry.InMemoryOrderLinks.Flink;
            }
            
            return entries;
        }

        private Tuple<IntPtr, IntPtr> ReadPeb(SafeProcessHandle processHandle)
        {
            if (_isWow64)
            {
                // Query the remote process for the address of the WOW64 PEB
                
                var processInformationBuffer = Marshal.AllocHGlobal(sizeof(long));
                
                var ntStatus = Ntdll.NtQueryInformationProcess(processHandle, ProcessInformationClass.Wow64Information, processInformationBuffer, sizeof(long), IntPtr.Zero);
                
                if (ntStatus != NtStatus.Success)
                {
                    throw new PInvokeException("Failed to call NtQueryInformationProcess", ntStatus);
                }
                
                var pebAddress = Marshal.ReadIntPtr(processInformationBuffer);
                
                Marshal.FreeHGlobal(processInformationBuffer);
                
                // Read the WOW64 PEB

                var peb = _memoryManager.ReadVirtualMemory<Peb32>(pebAddress);

                return new Tuple<IntPtr, IntPtr>((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }

            else
            {
                // Query the remote process for the address of the PEB
                
                var processInformationBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<ProcessBasicInformation>());
                
                var ntStatus = Ntdll.NtQueryInformationProcess(processHandle, ProcessInformationClass.BasicInformation, processInformationBuffer, Marshal.SizeOf<ProcessBasicInformation>(), IntPtr.Zero);
                
                if (ntStatus != NtStatus.Success)
                {
                    throw new PInvokeException("Failed to call NtQueryInformationProcess", ntStatus);
                }
                
                var pebAddress = Marshal.PtrToStructure<ProcessBasicInformation>(processInformationBuffer).PebBaseAddress;
                
                Marshal.FreeHGlobal(processInformationBuffer);
                
                // Read the WOW64 PEB

                var peb = _memoryManager.ReadVirtualMemory<Peb64>(pebAddress);

                return new Tuple<IntPtr, IntPtr>((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }
        }
    }
}
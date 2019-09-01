using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Bleak.Exceptions;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.Memory;
using Microsoft.Win32.SafeHandles;

namespace Bleak.RemoteProcess
{
    internal class PebManager
    {
        internal readonly IntPtr ApiSetMapAddress;

        private readonly bool _isWow64;

        private readonly IntPtr _loaderAddress;

        private readonly SafeProcessHandle _processHandle;

        internal PebManager(bool isWow64, SafeProcessHandle processHandle)
        {
            _isWow64 = isWow64;

            _processHandle = processHandle;

            var (apiSetMapAddress, loaderAddress) = ReadPebData();

            ApiSetMapAddress = apiSetMapAddress;

            _loaderAddress = loaderAddress;
        }

        internal Dictionary<IntPtr, LdrDataTableEntry64> GetPebEntries()
        {
            var entries = new Dictionary<IntPtr, LdrDataTableEntry64>();

            // Read the loader data of the PEB

            var pebLoaderData = MemoryManager.ReadVirtualMemory<PebLdrData64>(_processHandle, _loaderAddress);

            var currentEntryAddress = pebLoaderData.InMemoryOrderModuleList.Flink;

            var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry64>("InMemoryOrderLinks");

            while (true)
            {
                // Get the current entry of the InMemoryOrder linked list

                var entryAddress = currentEntryAddress - (int) inMemoryOrderLinksOffset;

                var entry = MemoryManager.ReadVirtualMemory<LdrDataTableEntry64>(_processHandle, (IntPtr) entryAddress);

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

            var pebLoaderData = MemoryManager.ReadVirtualMemory<PebLdrData32>(_processHandle, _loaderAddress);

            var currentEntryAddress = pebLoaderData.InMemoryOrderModuleList.Flink;

            var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry32>("InMemoryOrderLinks");

            while (true)
            {
                // Get the current entry of the InMemoryOrder linked list

                var entryAddress = currentEntryAddress - (int) inMemoryOrderLinksOffset;

                var entry = MemoryManager.ReadVirtualMemory<LdrDataTableEntry32>(_processHandle, (IntPtr) entryAddress);

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

        internal void UnlinkEntryFromPeb(IntPtr loaderEntryAddress)
        {
            if (_isWow64)
            {
                var loaderEntry = MemoryManager.ReadVirtualMemory<LdrDataTableEntry32>(_processHandle, loaderEntryAddress);

                // Remove the entry from the InLoadOrder, InMemoryOrder and InInitializationOrder linked lists

                RemoveDoublyLinkedListEntry(loaderEntry.InLoadOrderLinks);

                RemoveDoublyLinkedListEntry(loaderEntry.InMemoryOrderLinks);

                RemoveDoublyLinkedListEntry(loaderEntry.InInitializationOrderLinks);

                // Remove the entry from the LdrpHashTable

                RemoveDoublyLinkedListEntry(loaderEntry.HashLinks);
            }

            else
            {
                var loaderEntry = MemoryManager.ReadVirtualMemory<LdrDataTableEntry64>(_processHandle, loaderEntryAddress);

                // Remove the entry from the InLoadOrder, InMemoryOrder and InInitializationOrder linked lists

                RemoveDoublyLinkedListEntry(loaderEntry.InLoadOrderLinks);

                RemoveDoublyLinkedListEntry(loaderEntry.InMemoryOrderLinks);

                RemoveDoublyLinkedListEntry(loaderEntry.InInitializationOrderLinks);

                // Remove the entry from the LdrpHashTable

                RemoveDoublyLinkedListEntry(loaderEntry.HashLinks);
            }
        }

        private Tuple<IntPtr, IntPtr> ReadPebData()
        {
            if (_isWow64)
            {
                // Query the remote process for the address of the WOW64 PEB

                var processInformationBuffer = Marshal.AllocHGlobal(sizeof(long));

                var ntStatus = Ntdll.NtQueryInformationProcess(_processHandle, ProcessInformationClass.Wow64Information, processInformationBuffer, sizeof(long), IntPtr.Zero);

                if (ntStatus != NtStatus.Success)
                {
                    throw new PInvokeException("Failed to call NtQueryInformationProcess", ntStatus);
                }

                var pebAddress = Marshal.ReadIntPtr(processInformationBuffer);

                Marshal.FreeHGlobal(processInformationBuffer);

                // Read the WOW64 PEB

                var peb = MemoryManager.ReadVirtualMemory<Peb32>(_processHandle, pebAddress);

                return new Tuple<IntPtr, IntPtr>((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }

            else
            {
                // Query the remote process for the address of the PEB

                var processInformationBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<ProcessBasicInformation>());

                var ntStatus = Ntdll.NtQueryInformationProcess(_processHandle, ProcessInformationClass.BasicInformation, processInformationBuffer, Marshal.SizeOf<ProcessBasicInformation>(), IntPtr.Zero);

                if (ntStatus != NtStatus.Success)
                {
                    throw new PInvokeException("Failed to call NtQueryInformationProcess", ntStatus);
                }

                var pebAddress = Marshal.PtrToStructure<ProcessBasicInformation>(processInformationBuffer).PebBaseAddress;

                Marshal.FreeHGlobal(processInformationBuffer);

                // Read the WOW64 PEB

                var peb = MemoryManager.ReadVirtualMemory<Peb64>(_processHandle, pebAddress);

                return new Tuple<IntPtr, IntPtr>((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }
        }

        private void RemoveDoublyLinkedListEntry(ListEntry32 listEntry)
        {
            // Change the front link of the previous entry to the front link of the entry

            var previousEntry = MemoryManager.ReadVirtualMemory<ListEntry32>(_processHandle, (IntPtr) listEntry.Blink);

            previousEntry.Flink = listEntry.Flink;

            MemoryManager.WriteVirtualMemory(_processHandle, (IntPtr) listEntry.Blink, previousEntry);

            // Change the back link of the next entry to the back link of the entry

            var nextEntry = MemoryManager.ReadVirtualMemory<ListEntry32>(_processHandle, (IntPtr) listEntry.Flink);

            nextEntry.Blink = listEntry.Blink;

            MemoryManager.WriteVirtualMemory(_processHandle, (IntPtr) listEntry.Flink, nextEntry);
        }

        private void RemoveDoublyLinkedListEntry(ListEntry64 listEntry)
        {
            // Change the front link of the previous entry to the front link of the entry

            var previousEntry = MemoryManager.ReadVirtualMemory<ListEntry64>(_processHandle, (IntPtr) listEntry.Blink);

            previousEntry.Flink = listEntry.Flink;

            MemoryManager.WriteVirtualMemory(_processHandle, (IntPtr) listEntry.Blink, previousEntry);

            // Change the back link of the next entry to the back link of the entry

            var nextEntry = MemoryManager.ReadVirtualMemory<ListEntry64>(_processHandle, (IntPtr) listEntry.Flink);

            nextEntry.Blink = listEntry.Blink;

            MemoryManager.WriteVirtualMemory(_processHandle, (IntPtr) listEntry.Flink, nextEntry);
        }
    }
}
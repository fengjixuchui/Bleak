using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;

namespace Bleak.Injection.Methods
{
    internal sealed class LdrLoadDll : InjectionBase
    {
        internal LdrLoadDll(string dllPath, Process process, InjectionMethod injectionMethod, InjectionFlags injectionFlags) : base(dllPath, process, injectionMethod, injectionFlags) { }

        internal override void Eject()
        {
            if (InjectionFlags.HasFlag(InjectionFlags.HideDllFromPeb))
            {
                return;
            }

            var ldrUnloadDllAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "LdrUnloadDll");

            var ntStatus = ProcessManager.CallFunction<int>(CallingConvention.StdCall, ldrUnloadDllAddress, (long) DllBaseAddress);

            if ((NtStatus) ntStatus != NtStatus.Success)
            {
                throw new Win32Exception($"Failed to call LdrUnloadDll in the context of the remote process with error code {Ntdll.RtlNtStatusToDosError((NtStatus) ntStatus)}");
            }
        }

        internal override void Inject()
        {
            // Write the DLL path into the process

            var dllPathBytes = Encoding.Unicode.GetBytes(DllPath);

            var dllPathBuffer = ProcessManager.Memory.AllocateBlock(IntPtr.Zero, dllPathBytes.Length, ProtectionType.ReadWrite);

            ProcessManager.Memory.WriteBlock(dllPathBuffer, dllPathBytes);

            // Initialise a UnicodeString representing the DLL path in the process

            var dllPathUnicodeStringBuffer = ProcessManager.IsWow64
                                           ? ProcessManager.Memory.AllocateBlock(IntPtr.Zero, Unsafe.SizeOf<UnicodeString<int>>(), ProtectionType.ReadWrite)
                                           : ProcessManager.Memory.AllocateBlock(IntPtr.Zero, Unsafe.SizeOf<UnicodeString<long>>(), ProtectionType.ReadWrite);

            var rtlInitUnicodeStringAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "RtlInitUnicodeString");

            ProcessManager.CallFunction(CallingConvention.StdCall, rtlInitUnicodeStringAddress, (long) dllPathUnicodeStringBuffer, (long) dllPathBuffer);

            // Call LdrLoadDll in the process

            var ldrLoadDllAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "LdrLoadDll");

            var moduleHandleBuffer = ProcessManager.Memory.AllocateBlock(IntPtr.Zero, IntPtr.Size, ProtectionType.ReadWrite);

            var ntStatus = ProcessManager.CallFunction<int>(CallingConvention.StdCall, ldrLoadDllAddress, 0, 0, (long) dllPathUnicodeStringBuffer, (long) moduleHandleBuffer);

            if ((NtStatus) ntStatus != NtStatus.Success)
            {
                throw new Win32Exception($"Failed to call LdrLoadDll in the context of the remote process with error code {Ntdll.RtlNtStatusToDosError((NtStatus) ntStatus)}");
            }

            if (ProcessManager.IsWow64)
            {
                ProcessManager.Memory.FreeBlock((IntPtr) ProcessManager.Memory.Read<UnicodeString<int>>(dllPathUnicodeStringBuffer).Buffer);
            }

            else
            {
                ProcessManager.Memory.FreeBlock((IntPtr) ProcessManager.Memory.Read<UnicodeString<long>>(dllPathUnicodeStringBuffer).Buffer);
            }

            ProcessManager.Memory.FreeBlock(dllPathUnicodeStringBuffer);

            // Read the base address of the DLL that was loaded in the process

            DllBaseAddress = ProcessManager.Memory.Read<IntPtr>(moduleHandleBuffer);

            ProcessManager.Memory.FreeBlock(moduleHandleBuffer);

            if (InjectionFlags.HasFlag(InjectionFlags.HideDllFromPeb))
            {
                HideDllFromPeb();
            }

            if (InjectionFlags.HasFlag(InjectionFlags.RandomiseDllHeaders))
            {
                RandomiseDllHeaders();
            }
        }

        private void HideDllFromPeb()
        {
            var dllEntryAddress = IntPtr.Zero;

            if (ProcessManager.IsWow64)
            {
                foreach (var (entryAddress, entry) in ProcessManager.ReadWow64PebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = ProcessManager.Memory.ReadBlock((IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    if (entryFilePath == DllPath)
                    {
                        dllEntryAddress = entryAddress;

                        break;
                    }
                }

                var loaderEntry = ProcessManager.Memory.Read<LdrDataTableEntry<int>>(dllEntryAddress);

                // Remove the entry from the InLoadOrder, InMemoryOrder and InInitializationOrder linked lists

                RemoveDoublyLinkedListEntry(loaderEntry.InLoadOrderLinks);

                RemoveDoublyLinkedListEntry(loaderEntry.InMemoryOrderLinks);

                RemoveDoublyLinkedListEntry(loaderEntry.InInitializationOrderLinks);

                // Remove the entry from the LdrpHashTable

                RemoveDoublyLinkedListEntry(loaderEntry.HashLinks);

                // Zero out the FullDllName and BaseDllName buffers

                ProcessManager.Memory.WriteBlock((IntPtr) loaderEntry.FullDllName.Buffer, new byte[loaderEntry.FullDllName.Length]);

                ProcessManager.Memory.WriteBlock((IntPtr) loaderEntry.BaseDllName.Buffer, new byte[loaderEntry.BaseDllName.Length]);
            }

            else
            {
                foreach (var (entryAddress, entry) in ProcessManager.ReadPebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = ProcessManager.Memory.ReadBlock((IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    if (entryFilePath == DllPath)
                    {
                        dllEntryAddress = entryAddress;

                        break;
                    }
                }

                var loaderEntry = ProcessManager.Memory.Read<LdrDataTableEntry<long>>(dllEntryAddress);

                // Remove the entry from the InLoadOrder, InMemoryOrder and InInitializationOrder linked lists

                RemoveDoublyLinkedListEntry(loaderEntry.InLoadOrderLinks);

                RemoveDoublyLinkedListEntry(loaderEntry.InMemoryOrderLinks);

                RemoveDoublyLinkedListEntry(loaderEntry.InInitializationOrderLinks);

                // Remove the entry from the LdrpHashTable

                RemoveDoublyLinkedListEntry(loaderEntry.HashLinks);

                // Zero out the FullDllName and BaseDllName buffers

                ProcessManager.Memory.WriteBlock((IntPtr) loaderEntry.FullDllName.Buffer, new byte[loaderEntry.FullDllName.Length]);

                ProcessManager.Memory.WriteBlock((IntPtr) loaderEntry.BaseDllName.Buffer, new byte[loaderEntry.BaseDllName.Length]);
            }

            // Remove the entry for the DLL from the LdrpModuleBaseAddressIndex

            var rtlRbRemoveNodeAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "RtlRbRemoveNode");

            var ldrpModuleBaseAddressIndexAddress = PdbFile.Value.Symbols.First(symbol => symbol.Key.Contains("LdrpModuleBaseAddressIndex")).Value;

            ProcessManager.CallFunction(CallingConvention.StdCall, rtlRbRemoveNodeAddress, (long) ldrpModuleBaseAddressIndexAddress, (long) (dllEntryAddress + (int) Marshal.OffsetOf<LdrDataTableEntry<long>>("BaseAddressIndexNode")));
        }

        private void RemoveDoublyLinkedListEntry(ListEntry<int> listEntry)
        {
            // Change the front link of the previous entry to the front link of the entry

            var previousEntry = ProcessManager.Memory.Read<ListEntry<int>>((IntPtr) listEntry.Blink);

            previousEntry.Flink = listEntry.Flink;

            ProcessManager.Memory.Write((IntPtr) listEntry.Blink, previousEntry);

            // Change the back link of the next entry to the back link of the entry

            var nextEntry = ProcessManager.Memory.Read<ListEntry<int>>((IntPtr) listEntry.Flink);

            nextEntry.Blink = listEntry.Blink;

            ProcessManager.Memory.Write((IntPtr) listEntry.Flink, nextEntry);
        }

        private void RemoveDoublyLinkedListEntry(ListEntry<long> listEntry)
        {
            // Change the front link of the previous entry to the front link of the entry

            var previousEntry = ProcessManager.Memory.Read<ListEntry<long>>((IntPtr) listEntry.Blink);

            previousEntry.Flink = listEntry.Flink;

            ProcessManager.Memory.Write((IntPtr) listEntry.Blink, previousEntry);

            // Change the back link of the next entry to the back link of the entry

            var nextEntry = ProcessManager.Memory.Read<ListEntry<long>>((IntPtr) listEntry.Flink);

            nextEntry.Blink = listEntry.Blink;

            ProcessManager.Memory.Write((IntPtr) listEntry.Flink, nextEntry);
        }
    }
}
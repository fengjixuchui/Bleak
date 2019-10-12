using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.RemoteProcess.FunctionCall.Interfaces;
using Bleak.RemoteProcess.FunctionCall.Methods;
using Bleak.RemoteProcess.Structures;

namespace Bleak.RemoteProcess
{
    internal sealed class ProcessManager : IDisposable
    {
        internal readonly bool IsWow64;

        internal readonly Memory Memory;

        internal readonly List<Module> Modules;

        internal readonly Peb Peb;

        internal readonly Process Process;

        private readonly IFunctionCall _functionCall;

        internal ProcessManager(Process process, InjectionMethod injectionMethod)
        {
            Process = process;

            EnableDebuggerPrivileges();

            IsWow64 = GetProcessArchitecture();

            Memory = new Memory(process.SafeHandle);

            Peb = ReadPeb();

            Modules = GetModules();

            if (injectionMethod == InjectionMethod.CreateThread)
            {
                _functionCall = new CreateThread(Memory, process);
            }

            else
            {
                _functionCall = new HijackThread(Memory, process);
            }
        }

        public void Dispose()
        {
            Process.Dispose();
        }

        internal void CallFunction(CallingConvention callingConvention, IntPtr functionAddress, params long[] parameters)
        {
            _functionCall.CallFunction(new CallDescriptor(callingConvention, functionAddress, IsWow64, parameters, IntPtr.Zero));
        }

        internal TStructure CallFunction<TStructure>(CallingConvention callingConvention, IntPtr functionAddress, params long[] parameters) where TStructure : struct
        {
            var returnBuffer = Memory.AllocateBlock(IntPtr.Zero, Unsafe.SizeOf<TStructure>(), ProtectionType.ReadWrite);

            _functionCall.CallFunction(new CallDescriptor(callingConvention, functionAddress, IsWow64, parameters, returnBuffer));

            try
            {
                return Memory.Read<TStructure>(returnBuffer);
            }

            finally
            {
                Memory.FreeBlock(returnBuffer);
            }
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            var module = Modules.Find(m => m.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (module is null)
            {
                return IntPtr.Zero;
            }

            // Calculate the address of the function

            var function = module.PeImage.Value.ExportedFunctions.Find(f => f.Name != null && f.Name == functionName);

            var functionAddress = module.BaseAddress + function.Offset;

            // Determine if the function is forwarded to another function

            var exportDirectoryStartAddress = module.BaseAddress + module.PeImage.Value.Headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress;

            var exportDirectoryEndAddress = exportDirectoryStartAddress + module.PeImage.Value.Headers.PEHeader.ExportTableDirectory.Size;

            if ((long) functionAddress < (long) exportDirectoryStartAddress || (long) functionAddress > (long) exportDirectoryEndAddress)
            {
                return functionAddress;
            }

            // Read the forwarded function

            var forwardedFunctionBytes = new List<byte>();

            while (true)
            {
                var currentByte = Memory.Read<byte>(functionAddress);

                if (currentByte == byte.MinValue)
                {
                    break;
                }

                forwardedFunctionBytes.Add(currentByte);

                functionAddress += 1;
            }

            var forwardedFunction = Encoding.ASCII.GetString(forwardedFunctionBytes.ToArray()).Split(".");

            return GetFunctionAddress(forwardedFunction[0] + ".dll", forwardedFunction[1]);
        }

        internal IntPtr GetFunctionAddress(string moduleName, short functionOrdinal)
        {
            var module = Modules.Find(m => m.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (module is null)
            {
                return IntPtr.Zero;
            }

            // Determine the name of the function from its ordinal

            var function = module.PeImage.Value.ExportedFunctions.Find(f => f.Ordinal == functionOrdinal);

            return GetFunctionAddress(moduleName, function.Name);
        }

        internal Dictionary<IntPtr, LdrDataTableEntry<long>> ReadPebEntries()
        {
            var entries = new Dictionary<IntPtr, LdrDataTableEntry<long>>();

            // Read the loader data of the PEB

            var pebLoaderData = Memory.Read<PebLdrEntry<long>>(Peb.LoaderAddress);

            // Read the entries of the InMemoryOrder (circular) doubly linked list

            var currentEntryAddress = pebLoaderData.InMemoryOrderModuleList.Flink;

            var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry<long>>("InMemoryOrderLinks");

            while (true)
            {
                // Read the current entry

                var entryAddress = currentEntryAddress - (int) inMemoryOrderLinksOffset;

                var entry = Memory.Read<LdrDataTableEntry<long>>((IntPtr) entryAddress);

                entries.Add((IntPtr) entryAddress, entry);

                if (currentEntryAddress == pebLoaderData.InMemoryOrderModuleList.Blink)
                {
                    break;
                }

                // Determine the address of the next entry

                currentEntryAddress = entry.InMemoryOrderLinks.Flink;
            }

            return entries;
        }

        internal Dictionary<IntPtr, LdrDataTableEntry<int>> ReadWow64PebEntries()
        {
            var entries = new Dictionary<IntPtr, LdrDataTableEntry<int>>();

            // Read the loader data of the PEB

            var pebLoaderData = Memory.Read<PebLdrEntry<int>>(Peb.LoaderAddress);

            // Read the entries of the InMemoryOrder (circular) doubly linked list

            var currentEntryAddress = pebLoaderData.InMemoryOrderModuleList.Flink;

            var inMemoryOrderLinksOffset = Marshal.OffsetOf<LdrDataTableEntry<int>>("InMemoryOrderLinks");

            while (true)
            {
                // Read the current entry

                var entryAddress = currentEntryAddress - (int) inMemoryOrderLinksOffset;

                var entry = Memory.Read<LdrDataTableEntry<int>>((IntPtr) entryAddress);

                entries.Add((IntPtr) entryAddress, entry);

                if (currentEntryAddress == pebLoaderData.InMemoryOrderModuleList.Blink)
                {
                    break;
                }

                // Determine the address of the next entry

                currentEntryAddress = entry.InMemoryOrderLinks.Flink;
            }

            return entries;
        }

        internal void Refresh()
        {
            Modules.Clear();

            Modules.AddRange(GetModules());

            Process.Refresh();
        }

        private static void EnableDebuggerPrivileges()
        {
            try
            {
                Process.EnterDebugMode();
            }

            catch (Win32Exception)
            {
                // The local process isn't running in administrator mode
            }
        }

        private List<Module> GetModules()
        {
            var modules = new List<Module>();

            if (IsWow64)
            {
                var filePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                foreach (var entry in ReadWow64PebEntries().Values)
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = Memory.ReadBlock((IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                    var entryFilePath = filePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes), "SysWOW64");

                    // Read the name of the entry

                    var entryNameBytes = Memory.ReadBlock((IntPtr) entry.BaseDllName.Buffer, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    modules.Add(new Module((IntPtr) entry.DllBase, entryFilePath, entryName));
                }
            }

            else
            {
                foreach (var entry in ReadPebEntries().Values)
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = Memory.ReadBlock((IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    // Read the name of the entry

                    var entryNameBytes = Memory.ReadBlock((IntPtr) entry.BaseDllName.Buffer, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    modules.Add(new Module((IntPtr) entry.DllBase, entryFilePath, entryName));
                }
            }

            return modules;
        }

        private bool GetProcessArchitecture()
        {
            if (!Kernel32.IsWow64Process(Process.SafeHandle, out var isWow64Process))
            {
                throw new Win32Exception($"Failed to call IsWow64Process with error code {Marshal.GetLastWin32Error()}");
            }

            return isWow64Process;
        }

        private Peb ReadPeb()
        {
            if (IsWow64)
            {
                // Query the process for the address of its WOW64 PEB

                var wow64PebAddressBuffer = new byte[sizeof(long)];

                var ntStatus = Ntdll.NtQueryInformationProcess(Process.SafeHandle, ProcessInformationClass.Wow64Information, ref wow64PebAddressBuffer[0], wow64PebAddressBuffer.Length, out var returnLength);

                if (ntStatus != NtStatus.Success || returnLength != wow64PebAddressBuffer.Length)
                {
                    throw new Win32Exception($"Failed to call NtQueryInformationProcess with error code {ntStatus}");
                }

                var wow64PebAddress = Unsafe.ReadUnaligned<IntPtr>(ref wow64PebAddressBuffer[0]);

                // Read the WOW64 PEB

                var wow64Peb = Memory.Read<Peb<int>>(wow64PebAddress);

                return new Peb((IntPtr) wow64Peb.ApiSetMap, (IntPtr) wow64Peb.Ldr);
            }

            else
            {
                // Query the process for the address of its PEB

                var processBasicInformationBuffer = new byte[Unsafe.SizeOf<ProcessBasicInformation>()];

                var ntStatus = Ntdll.NtQueryInformationProcess(Process.SafeHandle, ProcessInformationClass.BasicInformation, ref processBasicInformationBuffer[0], processBasicInformationBuffer.Length, out var returnLength);

                if (ntStatus != NtStatus.Success || returnLength != processBasicInformationBuffer.Length)
                {
                    throw new Win32Exception($"Failed to call NtQueryInformationProcess with error code {ntStatus}");
                }

                var pebAddress = Unsafe.ReadUnaligned<ProcessBasicInformation>(ref processBasicInformationBuffer[0]).PebBaseAddress;

                // Read the PEB

                var peb = Memory.Read<Peb<long>>(pebAddress);

                return new Peb((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }
        }
    }
}
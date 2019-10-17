using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests
{
    public sealed class ManualMapTests : IDisposable
    {
        private readonly string _dllPath;

        private readonly Process _process;

        public ManualMapTests()
        {
            _dllPath = Path.Combine(Path.GetFullPath(@"..\..\..\TestDll\"), "TestDll.dll");

            _process = new Process {StartInfo = {CreateNoWindow = true, FileName = "notepad.exe", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden}};

            _process.Start();

            _process.WaitForInputIdle();
        }

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        [Fact]
        public void TestInject()
        {
            using var injector = new Injector(_process.Id, _dllPath, InjectionMethod.ManualMap);

            var dllBaseAddress = injector.InjectDll();

            Assert.NotEqual(dllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestWithRandomiseDllHeadersFlag()
        {
            using var injector = new Injector(_process.Id, _dllPath, InjectionMethod.ManualMap, InjectionFlags.RandomiseDllHeaders);

            var dllBaseAddress = injector.InjectDll();

            Assert.NotEqual(dllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestWithRandomiseDllNameFlag()
        {
            using var injector = new Injector(_process.Id, _dllPath, InjectionMethod.CreateThread, InjectionFlags.RandomiseDllName);

            var dllBaseAddress = injector.InjectDll();

            Assert.NotEqual(dllBaseAddress, IntPtr.Zero);
        }
    }
}
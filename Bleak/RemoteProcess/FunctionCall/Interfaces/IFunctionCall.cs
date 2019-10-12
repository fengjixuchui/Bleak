using Bleak.RemoteProcess.Structures;

namespace Bleak.RemoteProcess.FunctionCall.Interfaces
{
    internal interface IFunctionCall
    {
        void CallFunction(CallDescriptor callDescriptor);
    }
}
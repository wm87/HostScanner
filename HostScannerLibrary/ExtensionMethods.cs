using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace HostScannerLibrary
{
    public static class ExtensionMethods
    {
        public static string Format(this PhysicalAddress physicalAddress, string separator)
        {
            return Regex.Replace(physicalAddress.ToString(), "(..)(..)(..)(..)(..)(..)", "$1:$2:$3:$4:$5:$6");
        }
    }
}

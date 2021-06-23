using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace HostScannerLibrary
{
    public class HostScanner
    {
        #region Constructors

        public HostScanner() { }

        #endregion

        #region DataFields

        private readonly char[] _Separator = new char[] { '.' };

        private PhysicalAddress _PhysicalAddress;
        private IPHostEntry _IPHostEntry;
        private HostInformation _HostInformation;
        private List<Task> tasks = new List<Task>();

        #endregion

        #region Properties

        #endregion

        #region Methods

        public async Task ScanNetwork(string netAddress, string netMask)
        {
            await Task.Run(() =>
            {
                return ScanNetwork(IPAddress.Parse(netAddress), IPAddress.Parse(netMask));
            });
        }
        public async Task ScanNetwork(IPAddress netAddress, IPAddress netMask)
        {
            byte[] netAddressBytes = Array.ConvertAll(
                netAddress.ToString().Split(this._Separator, 4),
                octet => byte.Parse(octet)
            );

            byte[] netMaskBytes = Array.ConvertAll(
                netMask.ToString().Split(this._Separator, 4),
                octet => byte.Parse(octet)
            );

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                //Console.WriteLine("networkInterface.GetIPProperties().GatewayAddresses.Count: " + networkInterface.GetIPProperties().GatewayAddresses.Count);

                if (networkInterface.OperationalStatus == OperationalStatus.Up && networkInterface.GetIPProperties().GatewayAddresses.Count != 0)
                {
                    foreach (UnicastIPAddressInformation unicastIPAddressInformation in networkInterface.GetIPProperties().UnicastAddresses)
                    {
                        //Console.WriteLine("unicastIPAddressInformation.Address.AddressFamily " + unicastIPAddressInformation.Address.AddressFamily);

                        // AddressFamily.InterNetwork => ipv4
                        if (unicastIPAddressInformation.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            byte[] interfaceAddressBytes = Array.ConvertAll(
                                unicastIPAddressInformation.Address.ToString().Split(this._Separator, 4),
                                octet => byte.Parse(octet)
                            );

                            if
                                (
                                Convert.ToByte(netAddressBytes[0] & netMaskBytes[0]) == Convert.ToByte(interfaceAddressBytes[0] & netMaskBytes[0]) &&
                                Convert.ToByte(netAddressBytes[1] & netMaskBytes[1]) == Convert.ToByte(interfaceAddressBytes[1] & netMaskBytes[1]) &&
                                Convert.ToByte(netAddressBytes[2] & netMaskBytes[2]) == Convert.ToByte(interfaceAddressBytes[2] & netMaskBytes[2]) &&
                                Convert.ToByte(netAddressBytes[3] & netMaskBytes[3]) == Convert.ToByte(interfaceAddressBytes[3] & netMaskBytes[3])
                                )
                            {
                                byte[] lBoundAddressBytes = new byte[]
                                {
                                Convert.ToByte(netAddressBytes[0] & netMaskBytes[0]),
                                Convert.ToByte(netAddressBytes[1] & netMaskBytes[1]),
                                Convert.ToByte(netAddressBytes[2] & netMaskBytes[2]),
                                Convert.ToByte(netAddressBytes[3] & netMaskBytes[3])
                                };

                                // Netzadresse ergibt sich aus Ip-adresse und subnetzmaske mit Bitweise & 

                                string lBoundAddress = String.Join(".", lBoundAddressBytes);


                                byte[] uBoundAddressBytes = new byte[]
                                {
                                Convert.ToByte(lBoundAddressBytes[0] + 255 - netMaskBytes[0]),  // 192 + 255 - 255 => 192
                                Convert.ToByte(lBoundAddressBytes[1] + 255 - netMaskBytes[1]),  // 168 + 255 - 255 => 168
                                Convert.ToByte(lBoundAddressBytes[2] + 255 - netMaskBytes[2]),  // 178 + 255 - 255 => 178
                                Convert.ToByte(lBoundAddressBytes[3] + 255 - netMaskBytes[3])   // 0   + 255 - 0   => 255
                                };

                                string uBoundAddress = String.Join(".", uBoundAddressBytes);
                                string currentAddress;

                                // iteration durch vorher berechnetetes IP-Range

                                for (int octet0 = lBoundAddressBytes[0]; octet0 <= uBoundAddressBytes[0]; octet0++)
                                {
                                    for (int octet1 = lBoundAddressBytes[1]; octet1 <= uBoundAddressBytes[1]; octet1++)
                                    {
                                        for (int octet2 = lBoundAddressBytes[2]; octet2 <= uBoundAddressBytes[2]; octet2++)
                                        {
                                            for (int octet3 = lBoundAddressBytes[3]; octet3 <= uBoundAddressBytes[3]; octet3++)
                                            {
                                                currentAddress = String.Join(".", octet0, octet1, octet2, octet3);

                                                if (currentAddress != lBoundAddress && currentAddress != uBoundAddress)
                                                {
                                                    tasks.Add(ScanIPAddress(currentAddress));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            await Task.WhenAll(tasks);
        }


        public async Task<HostInformation> ScanIPAddress(string ipAddress)
        {
            return await Task.Run(() =>
            {
                return ScanIPAddress(IPAddress.Parse(ipAddress));
            });
        }

        public HostInformation ScanIPAddress(IPAddress ipAddress)
        {
            byte[] macBytes = new byte[6];
            uint macAddrLen = (uint)macBytes.Length;

            // (int)ipAddress.Address deprecated
            // int r = SendArp((int)ipAddress.Address, 0, macAddr, ref macAddrLen);
            // deshalb:
            // BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0) => kann ipv4 und ipv6, weil Konvertierung der IP-Adresse in 32bit oder 64bit möglich
            int r = SendArp(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macBytes, ref macAddrLen);

            // wenn SendArp nicht 0 als int zurückgibt, es das Kommand fehlerhaft => Exception wird geworfen
            // Summe der Bytes der MAC-Adresse muss größer als 0 sein
            if (r == 0 && macBytes.Sum(b => b) > 0)
            {
                this._PhysicalAddress = new PhysicalAddress(macBytes);
                this._IPHostEntry = null;

                try
                {
                    this._IPHostEntry = Dns.GetHostEntry(ipAddress);
                }
                catch { }

                this._HostInformation = new HostInformation(ipAddress, this._PhysicalAddress, this._IPHostEntry == null ? null : this._IPHostEntry.HostName.Split(this._Separator)[0].ToUpper());

                // Event "OnHostFound" wird gefeuert => es werden die aktuell, ermittelten Hostinformationen (MAC,IP,DNS) in die DB geschrieben werden
                this.OnHostFound(new HostFoundEventArgs(this._HostInformation));

                return this._HostInformation;
            }

            return null;
        }

        #endregion

        #region Events

        public delegate void HostFoundEventHandler(object sender, HostFoundEventArgs e);

        public event HostFoundEventHandler HostFound;

        protected void OnHostFound(HostFoundEventArgs e)
        {
            this.HostFound?.Invoke(this, e);
        }

        #endregion

        #region External

        [DllImport("iphlpapi.dll", EntryPoint = "SendARP", ExactSpelling = true)]
        private extern static int SendArp(int DestIP, int SrcIP, [Out] byte[] pMacAddr, ref uint PhyAddrLen);

        #endregion
    }

    #region Related

    public class HostFoundEventArgs : EventArgs
    {
        // TODO: TimeStamp

        #region Contructors

        public HostFoundEventArgs(HostInformation hostInformation)
        {
            _HostInformation = hostInformation;
        }

        #endregion

        #region DataFields

        private HostInformation _HostInformation;

        #endregion

        #region Properties

        public HostInformation HostInformation
        {
            get => this._HostInformation;
        }

        #endregion
    }

    public class HostInformation
    {
        #region Contructors

        public HostInformation(IPAddress IPAddress, PhysicalAddress PhysicalAddress, string DNSHostName)
        {
            this._IPAddress = IPAddress;
            this._PhysicalAddress = PhysicalAddress;
            this._DNSHostName = DNSHostName;
        }

        #endregion

        #region DataFields

        private IPAddress _IPAddress;
        private PhysicalAddress _PhysicalAddress;
        private string _DNSHostName;

        #endregion

        #region Properties

        public IPAddress IPAddress
        {
            get => this._IPAddress;
        }

        public PhysicalAddress PhysicalAddress
        {
            get => this._PhysicalAddress;
        }

        public string DNSHostName
        {
            get => this._DNSHostName;
        }

        #endregion
    }

    #endregion
}

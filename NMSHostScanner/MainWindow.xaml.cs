using HostScannerLibrary;
using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace NMSHostScanner
{
    /// <summary>
    /// Interaktionslogik für MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static MySqlConnection _Connection;

        private static Stopwatch sw;
        private static TimeSpan ts;
        private static string elapsedTime;

        private static int hostCnt = 0;

        private DataTable dt = new DataTable();
        HostScanner hs = new HostScanner();

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            hs.HostFound += Hs_HostFound;

            dt.Columns.Add("MAC", typeof(string));
            dt.Columns.Add("IP", typeof(string));
            dt.Columns.Add("DNS", typeof(string));
        }

        private void btnScan_Click(object sender, RoutedEventArgs e)
        {
            dgvHosts.ItemsSource = null;
            dt.Clear();

            lblHostCnt.Content = "";
            lblDuration.Content = "";

            _ = Scan(hs, txtIP, txtSubmask, lblDuration, btnScan);
        }

        private static async Task Scan(HostScanner hs, TextBox txtIP, TextBox txtSubmask, Label txtResult, Button btnScan)
        {
            btnScan.IsEnabled = false;
            btnScan.Content = "läuft";
            hostCnt = 0;
            sw = Stopwatch.StartNew();
            await Task.WhenAll(hs.ScanNetwork(txtIP.Text, txtSubmask.Text));
            sw.Stop();
            ts = sw.Elapsed;
            elapsedTime = String.Format("{0:00}:{1:00}:{2:00}", ts.Hours, ts.Minutes, ts.Seconds);
            txtResult.Content = elapsedTime;
            btnScan.Content = "Scan";
            btnScan.IsEnabled = true;
        }

        private static void IpScan(HostScanner hs)
        {
            List<string> ipList = new List<string>();

            MySqlDataReader reader;

            MySqlCommand cmd;
            string cmdTxt;

            // IP-Scan => jede Minute
            _ = hs.ScanIPAddress("192.168.178.30");
            cmdTxt = String.Format("SELECT ipv4 FROM hosts;");
            cmd = new MySqlCommand(cmdTxt, MainWindow._Connection);

            reader = cmd.ExecuteReader();

            while (reader.Read())
                ipList.Add(reader["ipv4"].ToString());

            reader.Close();

            int cnt = 1;
            foreach (string ip in ipList)
            {
                if (hs.ScanIPAddress(ip) == null)
                {
                    Console.WriteLine("ipv4 " + ip + " not available");
                    cmdTxt = string.Format("UPDATE hosts SET istAktiv='{0}' WHERE ipv4='{1}';", 0, ip);
                }
                else
                {
                    Console.WriteLine("ipv4 " + ip + " available");
                    cmdTxt = string.Format("UPDATE hosts SET istAktiv='{0}' WHERE ipv4='{1}';", 1, ip);
                }

                cmd = new MySqlCommand(cmdTxt, MainWindow._Connection);
                cmd.ExecuteNonQuery();

                Console.WriteLine();
                cnt++;
            }

            Console.WriteLine("IP-Scan beendet!");
        }

        private void Hs_HostFound(object sender, HostFoundEventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                dt.Rows.Add(e.HostInformation.PhysicalAddress.Format(":"), e.HostInformation.IPAddress, e.HostInformation.DNSHostName);
                dgvHosts.ItemsSource = dt.DefaultView;
                hostCnt++;
                lblHostCnt.Content = hostCnt;
            });

            //MySqlCommand command;
            //string commandText;

            //// Wenn Hostname vorhanden ist und die MAC-Adresse geändert wurde
            //// => Netzwerkkarte kaputt oder wurde ausgetauscht
            //commandText = String.Format(
            //    "UPDATE hosts SET mac='{0}', ipv4='{1}' WHERE hostname='{2}';",
            //    e.HostInformation.PhysicalAddress.Format(":"),
            //    e.HostInformation.IPAddress,
            //    e.HostInformation.DNSHostName
            //);
            //command = new MySqlCommand(commandText, Program._Connection);
            //command.ExecuteNonQuery();


            //commandText = String.Format(
            //    "SELECT count(*) AS Anzahl FROM hosts WHERE mac='{0}';",
            //    e.HostInformation.PhysicalAddress.Format(":")
            //);

            //command = new MySqlCommand(commandText, Program._Connection);

            //if (Convert.ToInt32(command.ExecuteScalar()) > 0)
            //{
            //    if (e.HostInformation.DNSHostName == null)
            //    {
            //        commandText = String.Format(
            //            "UPDATE hosts SET ipv4='{1}', hostname=null WHERE mac='{0}';",
            //            e.HostInformation.PhysicalAddress.Format(":"),
            //            e.HostInformation.IPAddress
            //        );
            //    }
            //    else
            //    {
            //        commandText = String.Format(
            //            "UPDATE hosts SET ipv4='{1}', hostname='{2}' WHERE MAC='{0}';",
            //            e.HostInformation.PhysicalAddress.Format(":"),
            //            e.HostInformation.IPAddress,
            //            e.HostInformation.DNSHostName
            //        );
            //    }

            //    command = new MySqlCommand(commandText, Program._Connection);
            //    command.ExecuteNonQuery();
            //}
            //else
            //{
            //    if (e.HostInformation.DNSHostName == null)
            //    {
            //        commandText = String.Format(
            //            "INSERT INTO hosts (mac, ipv4, fk_hostgr_id, fk_rolle_id) VALUES ('{0}', '{1}', 0, 0);",
            //            e.HostInformation.PhysicalAddress.Format(":"),
            //            e.HostInformation.IPAddress
            //        );
            //    }
            //    else
            //    {
            //        // durch Michael gegeben
            //        commandText = String.Format(
            //            "INSERT INTO hosts (mac, ipv4, hostname, fk_hostgr_id, fk_rolle_id) VALUES ('{0}', '{1}', '{2}', 0, 0);",
            //            e.HostInformation.PhysicalAddress.Format(":"),
            //            e.HostInformation.IPAddress,
            //            e.HostInformation.DNSHostName
            //        );
            //    }

            //    command = new MySqlCommand(commandText, Program._Connection);
            //    command.ExecuteNonQuery();
            //}
        }
    }
}
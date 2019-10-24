using System;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;


namespace NETSEC
{
    class Program
    {
        static void Main(string[] args)
        {
           
            var devices = CaptureDeviceList.Instance;

            if(devices.Count < 1)
            {
                Console.Write("\n\nIt's crazy how there's no network card on this machine!\n\n");
            }
            else
            {

                int idx = 0;
                int selection;

                Console.WriteLine("Pick a device to use");

                foreach(var device in devices)
                {
                    Console.WriteLine($"{idx}\t{device.Name} ({device.Description})");
                    idx++;
                }

                int.TryParse(Console.ReadLine(),out selection);

                var selected_device = devices[selection];
                
                //@ Watch for packet data
                selected_device.OnPacketArrival += new PacketArrivalEventHandler(handlePacketCapture);

                //@ start the device for capture
                int timeout = 2000;

                if(selected_device is LibPcapLiveDevice)
                {
                    var liveDevice = selected_device as LibPcapLiveDevice;
                    liveDevice.Open(DeviceMode.Promiscuous,timeout);
                    
                }
                else
                {
                    throw new Exception("\n\nNot configured to handle such devices!\n\n");
                }

                Console.WriteLine();
                Console.WriteLine($"-- Listening on {selected_device.Name} ({selected_device.Description}), hit 'Enter' to stop...");

                // Start the capturing process
                selected_device.StartCapture();

                // Wait for 'Enter' from the user.
                Console.ReadLine();

                // Stop the capturing process
                selected_device.StopCapture();

                Console.WriteLine("-- Capture stopped.");

                // Print out the device statistics
                Console.WriteLine(selected_device.Statistics.ToString());

                // Close the pcap device
                selected_device.Close();


            }

        }


        public static void handlePacketCapture(object senderInfo, CaptureEventArgs e)
        {
            var arrived_at      = e.Packet.Timeval.Date;
            var packet_length   = e.Packet.Data.Length;
            var device_info     = $"{e.Device.MacAddress} - {e.Device.Name}";
            string packet_data  = e.ToString();//     =  e.Packet.Data.CopyTo(info_arr);  // String.Join("****",e.Packet.Data);


            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);




            int pkt_counter = 0;
            foreach( var packetInfo in e.Packet.Data )
            {
                packet_data = $"{packet_data}\n{packetInfo} ";
                pkt_counter++;
            } 

            Console.WriteLine($"\n\n{device_info} @ {arrived_at.Hour}:{arrived_at.Minute}:{arrived_at.Second}:{arrived_at.Millisecond}\n({packet_length}\nData:{packet}");

        }
        
    }
}

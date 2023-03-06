
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Net;


namespace Example6
{
    public class DetectedConnections
    {
        public string srcIP;
        public string dstIP;
        public uint srcPort;
        public uint dstPort;
        public int indexID = 0;
        public int[] locID = new int[2];
        public uint acknum;
        public uint seqnum;
        public uint legalSeq;
        public bool onlyOne;
        public uint currrentPacket;
        public TcpPacket[] allPackets = new TcpPacket[32768];
    }
    public class DumpTCP
    {
        public static List<DetectedConnections> myDetectedConnection = new List<DetectedConnections>();
        private static int indexID = 0;
        private static int[] locID = new int[2];
        private static DateTime prevTime;
        private static int countOfPacket = 0;
        public static string resultOfScan = "";
        private static int i = 1;

        public static void Main(string[] args)
        {
            Console.Title = "Detect Changes in Lost Packet (updated)";
            Console.WriteLine("Если программа не работает (выдает исключение), то необходимо установить Npcap \n(в совместимом с Winpcap API режиме)");
            while (true)
            {
                try
                {
                    Console.WriteLine("Укажите путь к файлу, необходимому проанализировать");
                    CaptureFileReaderDevice fileReaderDevice = new CaptureFileReaderDevice(Console.ReadLine());
                    fileReaderDevice.Open();
                    fileReaderDevice.OnPacketArrival += new PacketArrivalEventHandler(DumpTCP.device_OnPacketArrival);
                    fileReaderDevice.StartCapture();
                    Console.ReadLine();
                    fileReaderDevice.StopCapture();
                    Console.WriteLine("-- Захват остановлен!");
                    fileReaderDevice.Close();
                    Console.ReadLine();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
            }
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            ++DumpTCP.countOfPacket;
            DateTime date = e.Packet.Timeval.Date;
            int length = e.Packet.Data.Length;
            try
            {
                TcpPacket encapsulated = TcpPacket.GetEncapsulated(Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data));
                if (encapsulated != null)
                {
                    if (((IpPacket)encapsulated.ParentPacket).Version.ToString() == "IPv4")
                    {
                        IPv4Packet parentPacket = (IPv4Packet)encapsulated.ParentPacket;
                        IPAddress sourceAddress = ((IpPacket)parentPacket).SourceAddress;
                        IPAddress destinationAddress = ((IpPacket)parentPacket).DestinationAddress;
                        string str1 = sourceAddress.ToString();
                        string str2 = destinationAddress.ToString();
                        int num1 = 0;
                        int index1 = 0;
                        int num2 = 0;
                        bool flag1 = false;
                        bool flag2 = false;
                        foreach (DetectedConnections detectedConnections in DumpTCP.myDetectedConnection)
                        {
                            if (str1 == detectedConnections.srcIP && str2 == detectedConnections.dstIP && (int)encapsulated.SourcePort == (int)detectedConnections.srcPort && (int)encapsulated.DestinationPort == (int)detectedConnections.dstPort)
                            {
                                index1 = num1;
                                detectedConnections.acknum = encapsulated.AcknowledgmentNumber;
                                detectedConnections.seqnum = encapsulated.SequenceNumber;
                                flag1 = true;
                            }
                            else if (str1 == detectedConnections.dstIP && str2 == detectedConnections.srcIP && (int)encapsulated.SourcePort == (int)detectedConnections.dstPort && (int)encapsulated.DestinationPort == (int)detectedConnections.srcPort)
                            {
                                num2 = num1;
                                flag2 = true;
                            }
                            ++num1;
                        }
                        if (!flag1)
                        {
                            DumpTCP.myDetectedConnection.Add(new DetectedConnections()
                            {
                                dstIP = str2,
                                srcIP = str1,
                                srcPort = (uint)encapsulated.SourcePort,
                                dstPort = (uint)encapsulated.DestinationPort
                            });
                            index1 = num1;
                        }
                        int id = (int)parentPacket.Id;
                        if (DumpTCP.myDetectedConnection[index1].allPackets[id] != null && encapsulated.PayloadData != DumpTCP.myDetectedConnection[index1].allPackets[id].PayloadData)
                        {
                            DumpTCP.resultOfScan = "Изменение в повторно отправленном пакете: ";
                            for (int index2 = 0; index2 < DumpTCP.myDetectedConnection[index1].allPackets[id].PayloadData.GetLength(0); ++index2)
                            {
                                    DumpTCP.resultOfScan = DumpTCP.resultOfScan + DumpTCP.myDetectedConnection[index1].allPackets[id].PayloadData[index2].ToString("X04").Substring(2, 2) + " "; 
                            }
                            DumpTCP.myDetectedConnection[index1].allPackets[id] = encapsulated;
                            if (DumpTCP.resultOfScan != "Изменение в повторно отправленном пакете: ")
                            {
                                Console.WriteLine(DumpTCP.resultOfScan);
                            }
                        }
                        else
                            DumpTCP.myDetectedConnection[index1].allPackets[id] = encapsulated;
                    }
                }
            }
            catch
            {
            }
            ++DumpTCP.i;
        }
    }
}

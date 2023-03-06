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
            Console.Title = "Detect Changes in Sequence Number (updated)";
            bool flag = false;
            Console.WriteLine("Если программа не работает (выдает исключение), то необходимо установить Npcap \n(в совместимом с Winpcap API режиме)");
            while (!flag)
            {
                try
                {
   
                    Console.WriteLine("Укажите путь к файлу, который необходимо проанализировать");
                    string path = Console.ReadLine();
                    CaptureFileReaderDevice fileReaderDevice = new CaptureFileReaderDevice(path);
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
                Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                TcpPacket encapsulated = TcpPacket.GetEncapsulated(packet);
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
                        int index2 = 0;
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
                                index2 = num1;
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
                        uint num2 = 0;
                        int id = (int)parentPacket.Id;
                        if (flag2)
                        {
                            if ((int)DumpTCP.myDetectedConnection[index2].acknum == (int)encapsulated.SequenceNumber)
                                num2 = encapsulated.SequenceNumber;
                            else if (DumpTCP.myDetectedConnection[index2].seqnum > encapsulated.AcknowledgmentNumber)
                            {
                                string[] strArray = new string[9]
                                {
                  "SourceIP: ",
                  DumpTCP.myDetectedConnection[index1].srcIP,
                  " DestinationIP: ",
                  DumpTCP.myDetectedConnection[index1].dstIP,
                  " Seq: ",
                  null,
                  null,
                  null,
                  null
                                };
                                uint sequenceNumber = encapsulated.SequenceNumber;
                                strArray[5] = sequenceNumber.ToString("X04").Substring(2, 2);
                                strArray[6] = " ";
                                sequenceNumber = encapsulated.SequenceNumber;
                                strArray[7] = sequenceNumber.ToString("X04").Substring(0, 2);
                                strArray[8] = "\n";
                                DumpTCP.resultOfScan = string.Concat(strArray);
                                Console.WriteLine(DumpTCP.resultOfScan);
                            }
                        }
                        else if (encapsulated.SequenceNumber == 0U)
                            num2 = encapsulated.SequenceNumber;
                        else if (!DumpTCP.myDetectedConnection[index1].onlyOne)
                        {
                            DumpTCP.myDetectedConnection[index1].onlyOne = true;
                            DumpTCP.myDetectedConnection[index1].currrentPacket = (uint)DumpTCP.i;
                        }
                        else if ((long)DumpTCP.i - (long)DumpTCP.myDetectedConnection[index1].currrentPacket > 1000L)
                        {
                            DumpTCP.myDetectedConnection[index1].currrentPacket = (uint)DumpTCP.i;
                        }
                        else
                        {
                            if (DumpTCP.myDetectedConnection[index1].allPackets[id] == null)
                            {
                                string[] strArray = new string[9]
                                {
                  "SourceIP: ",
                  DumpTCP.myDetectedConnection[index1].srcIP,
                  " DestinationIP: ",
                  DumpTCP.myDetectedConnection[index1].dstIP,
                  " Seq: ",
                  null,
                  null,
                  null,
                  null
                                };
                                uint sequenceNumber = encapsulated.SequenceNumber;
                                strArray[5] = sequenceNumber.ToString("X04").Substring(2, 2);
                                strArray[6] = " ";
                                sequenceNumber = encapsulated.SequenceNumber;
                                strArray[7] = sequenceNumber.ToString("X04").Substring(0, 2);
                                strArray[8] = "\n";
                                DumpTCP.resultOfScan = string.Concat(strArray);
                            }
                            else if ((int)encapsulated.SequenceNumber != (int)DumpTCP.myDetectedConnection[index1].allPackets[id].SequenceNumber)
                            {
                                string[] strArray = new string[9]
                                {
                  "SourceIP: ",
                  DumpTCP.myDetectedConnection[index1].srcIP,
                  " DestinationIP: ",
                  DumpTCP.myDetectedConnection[index1].dstIP,
                  " Seq: ",
                  null,
                  null,
                  null,
                  null
                                };
                                uint sequenceNumber = encapsulated.SequenceNumber;
                                strArray[5] = sequenceNumber.ToString("X04").Substring(2, 2);
                                strArray[6] = " ";
                                sequenceNumber = encapsulated.SequenceNumber;
                                strArray[7] = sequenceNumber.ToString("X04").Substring(0, 2);
                                strArray[8] = "\n";
                                DumpTCP.resultOfScan = string.Concat(strArray);
                            }
                            Console.WriteLine(DumpTCP.resultOfScan);
                        }
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

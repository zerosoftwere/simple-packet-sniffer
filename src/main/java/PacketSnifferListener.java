import org.pcap4j.packet.Packet;

import java.sql.Timestamp;

public interface PacketSnifferListener {
    void packetReceived(Packet packet, Timestamp timestamp);
}

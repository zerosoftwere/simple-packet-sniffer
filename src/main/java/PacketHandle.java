import org.pcap4j.packet.Packet;

import java.sql.Timestamp;

public class PacketHandle {
    private Packet packet;
    private Timestamp timestamp;

    public PacketHandle(Packet packet, Timestamp timestamp) {
        this.packet = packet;
        this.timestamp = timestamp;
    }

    public Packet getPacket() {
        return packet;
    }

    public void setPacket(Packet packet) {
        this.packet = packet;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }

    @Override
    public String toString() {
        return "PacketHandle{" +
                "packet=" + packet +
                ", timestamp=" + timestamp +
                '}';
    }
}

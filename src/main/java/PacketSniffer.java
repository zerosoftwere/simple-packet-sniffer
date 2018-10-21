import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;

import javax.activity.InvalidActivityException;
import java.util.ArrayList;
import java.util.List;

public class PacketSniffer {
    public static final int MAX_PACKET = 10_000;

    private PcapHandle handle;
    private List<PacketSnifferListener> sniffers = new ArrayList<>();

    public static List<PcapNetworkInterface> getNetworkDevices() {
        List<PcapNetworkInterface> devices = null;
        try {
            devices = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            e.printStackTrace();
        }
        return devices;
    }

    public void openDevice(PcapNetworkInterface device, String filter) throws PcapNativeException, NotOpenException  {
        if (device == null) {
            // We never get here
            return;
        }
        // Open the device and get a handle
        int snapshotLength = 65536; // in bytes
        int readTimeout = 50; // in milliseconds
        handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
    }

    void openOffline(String filename)  throws InvalidActivityException, PcapNativeException,
            NotOpenException, InterruptedException {
        if (handle != null && handle.isOpen()) throw
                new InvalidActivityException("Handle is opened");

        handle = Pcaps.openOffline(filename);
        startCapture();
        stopCapture();
    }

    void dumpPackets(ArrayList<PacketHandle> packets, String filename) throws PcapNativeException, NotOpenException {
        try (PcapHandle dumpHandle = Pcaps.openDead(DataLinkType.EN10MB, 65536)) {
            PcapDumper dumper = dumpHandle.dumpOpen(filename);
            for (PacketHandle packetHandle : packets) {
                dumper.dump(packetHandle.getPacket(), packetHandle.getTimestamp());
            }
        } catch (NotOpenException ex) {
            ex.printStackTrace();
        }
    }

    public void startCapture() throws InterruptedException, NotOpenException, PcapNativeException {
        // Create a listener that defines what to do with the received packets
        PacketListener listener = (packet) -> {
            for(PacketSnifferListener sniffer : sniffers)
                sniffer.packetReceived(packet, handle.getTimestamp());
        };
        handle.loop(MAX_PACKET, listener);
    }

    public void stopCapture() {
        if (!handle.isOpen()) {
            return;
        }

        try {
            handle.breakLoop();
            handle.close();
        } catch (NotOpenException ex) {
            System.out.println("Device not opened");
        }
    }

    public void getStatus() throws PcapNativeException, NotOpenException {
        PcapStat stats = handle.getStats();
        //TODO: Should return packet statistics ;)
    }

    public void addPacketSnifferListener(PacketSnifferListener listener) {
        this.sniffers.add(listener);
    }

    public void removePacketSnifferListener(PacketSnifferListener listener) {
        this.sniffers.remove(listener);
    }
}

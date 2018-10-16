import org.pcap4j.core.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

    public PcapHandle getHandle() {
        return this.handle;
    }

    public void addPacketSnifferListener(PacketSnifferListener listener) {
        this.sniffers.add(listener);
    }

    public void removePacketSnifferListener(PacketSnifferListener listener) {
        this.sniffers.remove(listener);
    }
}

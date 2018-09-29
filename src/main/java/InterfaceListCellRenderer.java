import org.pcap4j.core.PcapNetworkInterface;

import javax.swing.*;
import java.awt.*;

public class InterfaceListCellRenderer extends DefaultListCellRenderer {
    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {

        if (value instanceof PcapNetworkInterface) {
            PcapNetworkInterface device = (PcapNetworkInterface) value;
            String ipAddress = device.getAddresses().get(1).getAddress().getHostAddress();
            String description = device.getDescription();

            value = ipAddress + ' ' + description;
        }

        return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus); //To change body of generated methods, choose Tools | Templates.

    }
}

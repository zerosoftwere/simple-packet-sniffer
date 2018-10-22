import org.apache.commons.codec.binary.Hex;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.print.PrinterException;
import java.io.File;
import java.sql.Timestamp;
import java.util.ArrayList;

public class MainGUI {
    public static void main(String... args) {
        // Change look and feel to match windows use case
        for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels())
        {
            try {
                if (info.getName() == "Windows") {
                    UIManager.setLookAndFeel(info.getClassName());
                }
            } catch (Exception ex) {
                System.out.println("Using default java look and feel");
            }
        }

        // Display window frame
        EventQueue.invokeLater(() -> {
            JFrame frame = new SniffGUI();
            frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}

class SniffGUI extends JFrame implements PacketSnifferListener {
    public static final int DEFAULT_WIDTH = 800;
    public static final int DEFAULT_HEIGHT = 400;

    private PacketSniffer packetSniffer;
    private InfoComponent infoComponent;
    private JFileChooser fileChooser;

    private static final String[] columnNames = {
            "Time", "Source IP", "Destination IP", "Protocol", "Src Port", "Dst Port"
    };

    private JComboBox<PcapNetworkInterface> interfacesCB;
    private JTextField filterTF;
    private JButton startStopBT;
    private JTable infoTB;
    private DefaultTableModel infoTM;
    private ArrayList<PacketHandle> packets;

    private boolean isCapturing;
    private Thread sniffLoop;

    // Does setting up UI
    public SniffGUI() {
        setTitle("Packet Capture pre-alpha 1.0");
        setSize(DEFAULT_WIDTH, DEFAULT_HEIGHT);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                shouldClose();
            }
        });
        packets = new ArrayList<>(PacketSniffer.MAX_PACKET);

        JMenuBar menuBar = new JMenuBar();
        setJMenuBar(menuBar);

        JMenu fileMenu = new JMenu("File");
        menuBar.add(fileMenu);

        JMenuItem clearItem = new JMenuItem("Clear");
        clearItem.setAccelerator(KeyStroke.getKeyStroke("ctrl R"));
        clearItem.addActionListener(event -> clearCapturedPackets());
        fileMenu.add(clearItem);

        fileMenu.addSeparator();

        JMenuItem saveItem = new JMenuItem("Dump");
        saveItem.setAccelerator(KeyStroke.getKeyStroke("ctrl S"));
        saveItem.addActionListener(event -> saveCapturedPackets());
        fileMenu.add(saveItem);

        JMenuItem loadItem = new JMenuItem("Load");
        loadItem.setAccelerator(KeyStroke.getKeyStroke("ctrl O"));
        loadItem.addActionListener(event -> loadCapturedPackets());
        fileMenu.add(loadItem);

        fileMenu.addSeparator();

        JMenuItem printItem = new JMenuItem("print");
        printItem.setAccelerator(KeyStroke.getKeyStroke("ctrl P"));
        printItem.addActionListener(event -> printCapturedPackets());
        fileMenu.add(printItem);

        fileMenu.addSeparator();

        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.setAccelerator(KeyStroke.getKeyStroke("ctrl X"));
        exitItem.addActionListener(event -> shouldClose());
        fileMenu.add(exitItem);

        JPanel basicPanel = new JPanel();
        basicPanel.setLayout(new GridBagLayout());
        basicPanel.setBorder(BorderFactory.createTitledBorder("Basic"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 0;
        gbc.gridy = 0;
        basicPanel.add(new JLabel("Interface: "));

        interfacesCB = new JComboBox<>();
        interfacesCB.setRenderer(new InterfaceListCellRenderer());
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 50;
        gbc.insets = new Insets(0, 12, 0, 12);
        for (PcapNetworkInterface device : PacketSniffer.getNetworkDevices()) {
            interfacesCB.addItem(device);
        }
        basicPanel.add(interfacesCB, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        basicPanel.add(new JLabel("Filter: "));

        filterTF = new JTextField();
        gbc.gridx = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 50;
        gbc.insets = new Insets(0, 4, 0, 12);
        basicPanel.add(filterTF, gbc);

        startStopBT = new JButton("Start");
        gbc.gridx = 4;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        gbc.insets = new Insets(0, 0, 0, 0);
        basicPanel.add(startStopBT, gbc);
        startStopBT.addActionListener(event -> {
            if (isCapturing) {
                stopCapturing();
            } else {
                startCapturing();
            }
        });

        add(basicPanel, BorderLayout.NORTH);

        infoTM = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        infoTM.setColumnIdentifiers(columnNames);
        infoTB = new JTable(infoTM);
        infoTB.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        //Display selected packet information on the info pane
        infoTB.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            private int prevSelectedRow = -1;
            @Override
            public void valueChanged(ListSelectionEvent e) {
                int selectedRow = infoTB.getSelectedRow();
                if (selectedRow == prevSelectedRow) return;

                prevSelectedRow = selectedRow;
                if (selectedRow == -1) return;

                infoComponent.setPacketInfo(packets.get(selectedRow).getPacket());
            }
        });

        infoComponent = new InfoComponent();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(new JScrollPane(infoTB));
        splitPane.setBottomComponent(infoComponent);
        splitPane.setDividerLocation(0.8);
        splitPane.setResizeWeight(0.8);
        add(splitPane, BorderLayout.CENTER);

        packetSniffer = new PacketSniffer();
        packetSniffer.addPacketSnifferListener(this);


        fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File("."));
        fileChooser.setFileFilter(new FileFilter() {
            @Override
            public boolean accept(File f) {
                return f.isDirectory() || f.getName().endsWith(".pcap");
            }

            @Override
            public String getDescription() {
                return "pcap dump";
            }
        });
    }

    protected void shouldClose() {
        // Might accidentally clicked the X button?
        int result = JOptionPane.showConfirmDialog(
                SniffGUI.this, "Exit PacketSniffer?",
                "Quit", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            if (isCapturing) {
                packetSniffer.stopCapture();
            }
            System.exit(0);
        }
    }

    protected void stopCapturing() {
        // Enable Controls on capture stop.
        interfacesCB.setEnabled(true);
        filterTF.setEnabled(true);
        startStopBT.setText("Start");

        isCapturing = false;
        packetSniffer.stopCapture();
    }

    protected void startCapturing() {
        // Disable certain controls on capture start
        String filter  = filterTF.getText();
        PcapNetworkInterface device = (PcapNetworkInterface) interfacesCB.getSelectedItem();
        try {
            packetSniffer.openDevice(device, filter);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, ex);
        }

        interfacesCB.setEnabled(false);
        filterTF.setEnabled(false);
        startStopBT.setText("Stop ");

        clearCapturedPackets();

        // Sniff loop on a separate thread to prevent EDT from blocking
        sniffLoop = new Thread( () -> {
                try {
                    packetSniffer.startCapture();
                } catch (InterruptedException ex) {
                    packetSniffer.stopCapture();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, ex);
                }
            }
        );
        sniffLoop.start();
        isCapturing = true;
    }

    @Override
    public void packetReceived(Packet packet, Timestamp timestamp) {
        // Only interested in IPv4 packets
        if (packet.get(IpV4Packet.class) == null) {
            return;
        }

        String srcAddr, dstAddr, srcPort, dstPort, protocol, time;

        time = timestamp.toString();

        IpV4Packet.IpV4Header ethHeader = packet.get(IpV4Packet.class).getHeader();
        srcAddr = ethHeader.getSrcAddr().getHostAddress();
        dstAddr = ethHeader.getDstAddr().getHostAddress();
        protocol = ethHeader.getProtocol().name();

        if (packet.get(TcpPacket.class) != null) {
            TcpPacket.TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();
            srcPort = tcpHeader.getSrcPort().valueAsString();
            dstPort = tcpHeader.getDstPort().valueAsString();
        }
        else if (packet.get(UdpPacket.class) != null) {
            UdpPacket.UdpHeader header = packet.get(UdpPacket.class).getHeader();
            srcPort = header.getSrcPort().valueAsString();
            dstPort = header.getDstPort().valueAsString();
        }
        else {
            srcPort = dstPort = "";
        }

        infoTM.addRow(new String[] {time, srcAddr, dstAddr, protocol, srcPort, dstPort});
        packets.add(new PacketHandle(packet, timestamp));
    }

    protected void clearCapturedPackets() {
        infoTB.clearSelection();
        infoTM.setRowCount(0);
        packets.clear();
        infoComponent.clear();
    }

    protected void loadCapturedPackets() {
        if (isCapturing) {
            int result = JOptionPane.showConfirmDialog(this,
                    "Packet Capturing is in progress\nDiscard current session?",
                    "Capture In Progress", JOptionPane.WARNING_MESSAGE);
            if (result != JOptionPane.OK_OPTION)
                return;
        }

        stopCapturing();
        clearCapturedPackets();

        fileChooser.setSelectedFile(new File(""));
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                String filename = fileChooser.getSelectedFile().getAbsolutePath();
                packetSniffer.openOffline(filename);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, ex);
            }
        }
    }

    protected void saveCapturedPackets() {
        if (isCapturing) {
            int result = JOptionPane.showConfirmDialog(this,
                    "New packets will not be saved\nContinue?",
                    "Capture in progress", JOptionPane.WARNING_MESSAGE);
            if (result != JOptionPane.OK_OPTION)
                return;
        }
        if (packets.size() == 0) {
            JOptionPane.showMessageDialog(this, "Nothing to save", "No Packets", JOptionPane.ERROR_MESSAGE);
            return;
        }

        fileChooser.setSelectedFile(new File("untitled.pcap"));
        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                String filename = fileChooser.getSelectedFile().getAbsolutePath();
                if (!filename.endsWith("pcap")) filename.concat(".pcap");

                packetSniffer.dumpPackets(packets, filename);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, ex);
            }
        }
    }

    protected void printCapturedPackets() {
        try {
            infoTB.print();
        } catch (PrinterException ex) {
            JOptionPane.showMessageDialog(this, ex);
        }
    }
}

class InfoComponent extends JTabbedPane {
    private JTextArea ethInfoArea;
    private JTextArea ipInfoArea;
    private JTextArea payloadArea;

    public InfoComponent() {

        ethInfoArea = new JTextArea();
        ethInfoArea.setEditable(false);
        add("Eth Header", new JScrollPane(ethInfoArea));

        ipInfoArea = new JTextArea();
        ipInfoArea.setEditable(false);
        add("IP Header", new JScrollPane(ipInfoArea));

        payloadArea = new JTextArea();
        payloadArea.setEditable(false);
        payloadArea.setLineWrap(true);
        add("Payload", new JScrollPane(payloadArea));

    }

    public void setPacketInfo(Packet packet) {
        Packet.Header ethHeader = packet.getHeader();
        setEthHeaderInfo(ethHeader);

        IpV4Packet.IpV4Header ipHeader = packet.get(IpV4Packet.class).getHeader();
        setIpHeaderInfo(ipHeader);

        setPayloadInfo(packet.getPayload());
    }

    protected void setEthHeaderInfo(Packet.Header header) {
        ethInfoArea.setText(header.toString());
    }

    protected void setIpHeaderInfo(IpV4Packet.IpV4Header header) {
        ipInfoArea.setText(header.toString());
    }

    protected void setPayloadInfo(Packet packet) {
        String hex = Hex.encodeHexString(packet.getRawData());
        payloadArea.setText(hex);
    }

    public void clear() {
        ethInfoArea.setText("");
        ipInfoArea.setText("");
        payloadArea.setText("");
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(300, 100);
    }
}


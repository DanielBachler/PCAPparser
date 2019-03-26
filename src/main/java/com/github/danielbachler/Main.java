package com.github.danielbachler;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;

import java.io.IOException;
import java.util.HashMap;

/**
 * Daniel Bachler
 * CSCI-476 Assignment 4
 * This program takes in a file name from command line and finds all the TCP packets.
 * Then it uses some logic to determine if any IP's are conducting a port scan of the system the file is from.
 */

public class Main {
    //Data structure for storing sent SYN packets
    private static HashMap<String, Integer> dataSent = new HashMap<String, Integer>();
    private static HashMap<String, Integer> dataReceived = new HashMap<String, Integer>();


    public static void main(String[] args) throws IOException {

        //Opens given packet file
        final Pcap pcap = Pcap.openStream(args[0]);
        //Opens given packet file (Debugging version)
        //final Pcap pcap = Pcap.openStream("capture.pcap");

        //Loops through all packets in given file
        pcap.loop(new PacketHandler() {
            @Override
            public boolean nextPacket(Packet packet) throws IOException {
                //Only pulls TCP packets as they are the only ones we care about for this assignment
                if (packet.hasProtocol(Protocol.TCP)) {
                    //Gets the packet and converts it into a TCPPacket
                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    //Calls processPacket to deal with this TCP packet
                    Main.processPacket(tcpPacket);
                }
                return true;
            }
        });

        //Sort through data for useful information
        processInformation();
    }

    //Deals with the packets once pulled from source file
    private static void processPacket(TCPPacket tcppaket) {
        //Gets source and destination IP
        String src = tcppaket.getSourceIP();
        String dest = tcppaket.getDestinationIP();

        //Pulls any existing stats from dataSent and modifies as needed
        if(dataSent.containsKey(src)) {
            //Gets the current count of SYN only packets sent from this IP
            int temp = dataSent.get(src);
            //If only the SYN flag is active, increment count by one
            if(tcppaket.isSYN() && !tcppaket.isACK()) {
                temp += 1;
            }
            //Restore the data with new values
            dataSent.put(src, temp);
        }
        //If no entry exists, creates one
        else {
            //Only makes new entry on valid packet
            if(tcppaket.isSYN() && !tcppaket.isACK())
                dataSent.put(src, 1);
        }

        //Pulls any existing stats from dataReceived and modifies as needed
        if(dataReceived.containsKey(dest)) {
            //Gets the current count of received SYN+ACK packets
            int temp = dataReceived.get(dest);
            //If both flags are active, increments counter by one
            if(tcppaket.isSYN() && tcppaket.isACK()) {
                temp += 1;
            }
            //Restores new data
            dataReceived.put(dest, temp);
        }
        //If no entry exists, creates one
        else {
            if(tcppaket.isACK() && tcppaket.isSYN())
                dataReceived.put(dest, 1);
        }
    }

    private static void processInformation() {
        //Iterates through all keys in dataSent
        for(String key: dataSent.keySet()) {
            //Gets the total number of SYN packets sent
            int sentSYN = dataSent.get(key);
            //If the dataReceived contains that key
            if(dataReceived.containsKey(key)) {
                //Pull SYN+ACK response packets and check ratio.  If 3x more SYN only packets are sent then print IP
                int receivedSYNACK = dataReceived.get(key) * 3;
                if (sentSYN >= receivedSYNACK) {
                    System.out.println(key);
                }
            }
        }
    }
}

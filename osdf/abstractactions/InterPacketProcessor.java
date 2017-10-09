/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.incubator.net.osdf.abstractactions;


import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.ARP;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.incubator.net.osdf.interrouteconfigs.InterRouteConfigurationService;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicy;
import org.onosproject.incubator.net.osdf.policies.Policy;
import org.onosproject.incubator.net.osdf.policystorage.PolicyService;
import org.onosproject.incubator.net.osdf.statuscodes.StatusCodes;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.region.Region;
import org.onosproject.net.region.RegionService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.Iterator;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Packet Processor for inter-domain abstract operations.
 */


@Component(immediate = true)
@Service
public class InterPacketProcessor extends AbstractAction implements RouteActionInterface {


    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected RegionService regionService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PolicyService policyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected InterRouteConfigurationService config;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService configService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected InterRouteActionInterface interRouteActionInterface;

    private ApplicationId appId;
    private RoutingPacketProcessor processor = new RoutingPacketProcessor();


    @Activate
    public void activate(ComponentContext context) {
        log.info("Started");
        appId = coreService.registerApplication("org.onosproject.PolicyBasedPacketProcessor");
        packetService.addProcessor(processor, org.onosproject.net.packet.PacketProcessor.director(3));
        requestIntercepts();
    }

    @Deactivate
    public void deactivate() {
        log.info("Stopped");
        withdrawIntercepts();

    }


    @Modified
    public void modified(ComponentContext context) {

        requestIntercepts();
    }

    /**
     * Request packet in via packet service.
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

    }

    /**
     * Cancel request for packet in via packet service.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

    }

    /**
     * Checks an Ethernet Packet is a control packet or not.
     *
     * @param eth Ethernet packet
     * @return type of a control packet
     */
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();

        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }


    /**
     * Packet processor responsible for extracting low level match fields
     * based on current active polices.
     */
    private class RoutingPacketProcessor implements org.onosproject.net.packet.PacketProcessor {

        Iterator<Policy> policyIterator;

        private StatusCodes checkCurrentPolicies() {
            policyIterator = policyService.getCurrentPolicies().iterator();
            if (policyIterator.hasNext()) {

                return StatusCodes.STATUS_OK;

            }

            return StatusCodes.STATUS_ERR;

        }


        @Override
        public void process(PacketContext context) {

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();


            if (isControlPacket(ethPkt)) {
                return;
            }
            if (ethPkt == null) {
                return;
            }


            Ip4Prefix ip4SrcPrefix = null;
            Ip4Prefix ip4DstPrefix = null;
            ConnectPoint srcConnectPoint = pkt.receivedFrom();
            switch (EthType.EtherType.lookup(ethPkt.getEtherType())) {

                case ARP:
                    ARP arpPacket = (ARP) ethPkt.getPayload();
                    Ip4Address targetIpAddress = Ip4Address
                            .valueOf(arpPacket.getTargetProtocolAddress());
                    // Only when it is an ARP request packet and the target IP
                    // address is a virtual gateway IP address, then it will be
                    // processed.

                    if (config.isVirtualGatewayIpAddress(targetIpAddress)) {
                        log.debug(targetIpAddress.toString());
                    }
                    if (arpPacket.getOpCode() == ARP.OP_REQUEST
                            && config.isVirtualGatewayIpAddress(targetIpAddress)) {
                        MacAddress gatewayMacAddress =
                                config.getVirtualGatewayMacAddress();

                        //log.debug("MAC gw:" + gatewayMacAddress.toString());
                        if (gatewayMacAddress == null) {
                            //log.debug("null gateway");
                            break;
                        }

                        Ethernet eth = ARP.buildArpReply(targetIpAddress,
                                gatewayMacAddress,
                                ethPkt);

                        TrafficTreatment.Builder builder =
                                DefaultTrafficTreatment.builder();
                        builder.setOutput(srcConnectPoint.port());
                        packetService.emit(new DefaultOutboundPacket(
                                srcConnectPoint.deviceId(),
                                builder.build(),
                                ByteBuffer.wrap(eth.serialize())));
                    }
                    break;

                case IPV4:
                    IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();

                    ip4SrcPrefix =
                            Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                    24);
                    ip4DstPrefix =
                            Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                    24);

                    Region policysrcRegion;
                    Region policydstRegion;
                    String pktSrcRegion;
                    String pktDstRegion;

                    DefaultPolicy policy;
                    ActionList action;
                    //log.info("IPv4 packet");
                    if (checkCurrentPolicies() == StatusCodes.STATUS_OK) {

                        policyIterator = policyService.getCurrentPolicies().iterator();
                        while (policyIterator.hasNext()) {

                            if (policyIterator.hasNext()) {
                                policy = (DefaultPolicy) policyIterator.next();
                            } else {
                                continue;
                            }

                            action = policy.getAction();
                            pktSrcRegion = config.getRegion(ip4SrcPrefix);
                            pktDstRegion = config.getRegion(ip4DstPrefix);
                            policysrcRegion = policy.getSrcRegion();
                            policydstRegion = policy.getDstRegion();

                            if (action == ActionList.INTER_ROUTE && ((policysrcRegion.id().toString().equals(pktSrcRegion)
                                    && policydstRegion.id().toString().equals(pktDstRegion))
                                    || (policysrcRegion.id().toString().equals(pktDstRegion)
                                    && policydstRegion.id().toString().equals(pktSrcRegion)))) {
                                interRouteActionInterface.interRouteProcess(policy, context);

                            }

                        }
                    }

                    break;
                default:
                    break;

            }


        }


    }
}

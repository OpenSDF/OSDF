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
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.incubator.net.osdf.interrouteconfigs.InterRouteConfigurationService;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicy;
import org.onosproject.incubator.net.osdf.policyparser.PathSelectionInterface;
import org.onosproject.incubator.net.osdf.policyparser.PolicyParserInterface;
import org.onosproject.incubator.net.osdf.policystorage.PolicyService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.region.RegionService;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;

import java.util.List;
import java.util.Set;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Inter-route network traffic between regions.
 */
@Component(immediate = true)
@Service
public class InterRouteAction
        extends AbstractAction
        implements InterRouteActionInterface {


    private static final String APP_NAME = "org.onosproject.InterRouting";

    private static final int DEFAULT_TIMEOUT = 100;
    private static final int DEFAULT_PRIORITY = 10;
    private static final int TABLE_ID = 0;
    private final Logger log = getLogger(getClass());

    /**
     * Link service instance.
     */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected LinkService linkService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService networkConfigService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected RegionService regionService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PolicyService policyService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PathSelectionInterface pathSelection;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected InterRouteConfigurationService config;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService configService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private PolicyParserInterface policyParser;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private PacketService packetService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private CoreService coreService;
    private int flowTimeout = DEFAULT_TIMEOUT;
    private int flowPriority = DEFAULT_PRIORITY;
    private ApplicationId appId;


    /**
     * Service activation method.
     *
     * @param context component context
     */
    @Activate
    public void activate(ComponentContext context) {
        log.info("Started");
        appId = coreService.registerApplication(APP_NAME);
        requestIntercepts();
    }

    /**
     * Service Deactivation method.
     */
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
     * @param eth Ethernet packet.
     * @return type of a control packet.
     */
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }


    /**
     * Local inter route function to install OpenFlow rules based
     * on high level policies.
     *
     * @param pkt     Inbound packet
     * @param ethPkt  Ethernet packet
     * @param context packet context
     */
    private void localInterRoute(DefaultPolicy policy,
                                 InboundPacket pkt,
                                 Ethernet ethPkt,
                                 PacketContext context) {

        IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
        IpAddress dstIp =
                IpAddress.valueOf(ipv4Packet.getDestinationAddress());

        MacAddress srcMac = ethPkt.getSourceMAC();
        MacAddress dstMac = null;
        ConnectPoint dstConnectPoint;
        for (Host host : hostService.getHostsByIp(dstIp)) {
            if (host.mac() != null) {
                dstMac = host.mac();
                dstConnectPoint = host.location();
                break;
            }
        }
        if (dstMac == null) {
            hostService.startMonitoringIp(dstIp);
            return;
        }


        List<Link> pathLinks = null;
        HostId dstId = HostId.hostId(dstMac);
        HostId srcId = HostId.hostId(srcMac);
        Host dst = hostService.getHost(dstId);
        Host src = hostService.getHost(srcId);


        TrafficTreatment treatment = null;
        TrafficSelector.Builder builderSelector;
        Path endPath = null;

        int priority = policy.getPriority();
        if (src.location().deviceId().equals(dst.location().deviceId())) {
            builderSelector = policyParser.interBuildTrafficSelector(pkt, ethPkt, dstMac, policy);
            if (builderSelector != null) {
                treatment = DefaultTrafficTreatment.
                        builder()
                        .setOutput(dst.location().port())
                        .build();
                DefaultFlowRule flowRule;
                flowRule = (DefaultFlowRule) DefaultFlowRule.builder()
                        .withPriority(policy.getPriority())
                        .makeTemporary(flowTimeout).forDevice(dst.location().deviceId())
                        .withSelector(builderSelector.build()).withTreatment(treatment)
                        .fromApp(appId).forTable(TABLE_ID)
                        .build();
                flowRuleService.applyFlowRules(flowRule);
                policyService.addFlowRule(policy, flowRule);
            }

                            /*try {
                                Thread.sleep(10 * policyService.getRulesCount(policy));

                            } catch (InterruptedException e) {
                                log.info(e.getLocalizedMessage());
                            }*/
            forwardPacketToDst(context, dst.location());
            //context.treatmentBuilder().setOutput(dst.location().port());
            //context.send();

        } else {
            Set<Path> endToEndPaths =
                    topologyService.getPaths(topologyService.currentTopology(),
                            src.location().deviceId(),
                            dst.location().deviceId());
            switch (policy.getPathSelectionAlgo()) {
                case ON_DEMAND:
                    endPath = pathSelection.getEndtoEndPath(endToEndPaths, policy);
                    break;
                case RANDOM:
                    endPath = pathSelection.pickRandomPath(endToEndPaths, policy);
                    break;
                case BEST_POSSIBLE_PATH:
                    endPath = pathSelection.getEndtoEndPath(endToEndPaths, policy);
                    break;
                default:
                    endPath = pathSelection.getEndtoEndPath(endToEndPaths, policy);
                    break;
            }
            pathLinks = endPath.links();
            Link lastLink = pathLinks.get(pathLinks.size() - 1);
            Link firstLink = pathLinks.get(0);
            for (Link link : pathLinks) {

                builderSelector = policyParser.interBuildTrafficSelector(pkt,
                        ethPkt,
                        dstMac,
                        policy);
                if (builderSelector != null && link.equals(firstLink)) {
                    treatment = DefaultTrafficTreatment.
                            builder().setEthDst(dstMac)
                            .setOutput(link.src().port())
                            .build();
                    DefaultFlowRule flowRule;
                    flowRule = (DefaultFlowRule) DefaultFlowRule.builder()
                            .withPriority(priority).makeTemporary(flowTimeout)
                            .forDevice(link.src().deviceId()).withSelector(builderSelector.build())
                            .withTreatment(treatment)
                            .fromApp(appId).forTable(TABLE_ID)
                            .build();
                    flowRuleService.applyFlowRules(flowRule);
                    policyService.addFlowRule(policy, flowRule);
                    if (lastLink.equals(link)) {
                        treatment = DefaultTrafficTreatment.
                                builder()
                                .setOutput(dst.location().port())
                                .build();
                        flowRule = (DefaultFlowRule) DefaultFlowRule.builder()
                                .withPriority(priority)
                                .makeTemporary(flowTimeout)
                                .forDevice(dst.location().deviceId())
                                .withSelector(builderSelector.build())
                                .withTreatment(treatment)
                                .fromApp(appId)
                                .forTable(TABLE_ID)
                                .build();
                        flowRuleService.applyFlowRules(flowRule);
                        policyService.addFlowRule(policy, flowRule);
                    }

                } else if (builderSelector != null) {

                    treatment = DefaultTrafficTreatment.
                            builder()
                            .setOutput(link.src().port())
                            .build();

                    DefaultFlowRule flowRule;
                    flowRule = (DefaultFlowRule) DefaultFlowRule
                            .builder()
                            .withPriority(priority).makeTemporary(flowTimeout)
                            .forDevice(link.src().deviceId()).withSelector(builderSelector.build())
                            .withTreatment(treatment).fromApp(appId)
                            .forTable(TABLE_ID)
                            .build();

                    flowRuleService.applyFlowRules(flowRule);
                    policyService.addFlowRule(policy, flowRule);
                    if (lastLink.equals(link)) {
                        treatment = DefaultTrafficTreatment
                                .builder()
                                .setOutput(dst.location().port())
                                .build();
                        flowRule = (DefaultFlowRule) DefaultFlowRule
                                .builder()
                                .withPriority(priority).makeTemporary(flowTimeout)
                                .forDevice(dst.location().deviceId())
                                .withSelector(builderSelector.build())
                                .withTreatment(treatment).fromApp(appId)
                                .forTable(TABLE_ID)
                                .build();
                        flowRuleService.applyFlowRules(flowRule);
                        policyService.addFlowRule(policy, flowRule);
                    }
                }
            }
                            /*try {
                                Thread.sleep(10 * policyService.getRulesCount(policy));

                            } catch (InterruptedException e) {
                                log.info(e.getLocalizedMessage());
                            }*/

            forwardPacketToDst(context, firstLink.src());
            //context.treatmentBuilder().setOutput(firstLink.src().port());
            //context.send();

        }


    }

    private void forwardPacketToDst(PacketContext context,
                                    ConnectPoint connectPoint) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(connectPoint.port()).build();
        OutboundPacket packet =
                new DefaultOutboundPacket(connectPoint.deviceId(), treatment,
                        context.inPacket().unparsed());
        packetService.emit(packet);
    }


    /**
     * Inter-route processor.
     *
     * @param context packet processing context
     */

    public void interRouteProcess(DefaultPolicy policy, PacketContext context) {

        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();


        if (ethPkt == null) {
            return;
        }

        switch (EthType.EtherType.lookup(ethPkt.getEtherType())) {
            case IPV4:
                localInterRoute(policy, pkt, ethPkt, context);

                break;
            default:
                break;

        }


    }


}

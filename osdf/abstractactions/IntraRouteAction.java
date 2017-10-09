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
import org.onlab.packet.Ethernet;
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
 * Route data traffic based on a high level network policy inside a local region.
 */


@Component(immediate = true)
@Service
public class IntraRouteAction extends AbstractAction implements IntraRouteActionInterface {


    private static final int DEFAULT_TIMEOUT = 10;
    private static final int DEFAULT_PRIORITY = 10;
    private static final int TABLE_ID = 0;
    private final Logger log = getLogger(getClass());
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected LinkService linkService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService networkConfigService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;
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
    protected FlowRuleService flowRuleService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected InterRouteConfigurationService config;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService configService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private PolicyParserInterface policyParser;
    private int flowTimeout = DEFAULT_TIMEOUT;
    private int flowPriority = DEFAULT_PRIORITY;

    private ApplicationId appId;


    @Activate
    public void activate(ComponentContext context) {
        log.info("Started");
        appId = coreService.registerApplication("org.onosproject.PolicyBasedRouting");
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

        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN || type == Ethernet.TYPE_ARP;
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


    public void intraRouteProcess(DefaultPolicy policy, PacketContext context) {

        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();


        log.info("intra process is called");

        if (isControlPacket(ethPkt)) {
            return;
        }
        if (ethPkt == null) {
            return;
        }



        HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
        HostId srcId = HostId.hostId(ethPkt.getSourceMAC());
        Host dst = hostService.getHost(dstId);
        Host src = hostService.getHost(srcId);
        List<Link> pathLinks = null;
        if (src == null || dst == null) {
            return;
        }



        TrafficTreatment treatment;
        TrafficSelector.Builder builderSelector;
        Path endPath;

        if (src.location().deviceId().equals(dst.location().deviceId())) {
            builderSelector = policyParser.intraBuildTrafficSelector(pkt,
                    ethPkt,
                    null,
                    policy);
            if (builderSelector != null) {
                treatment = DefaultTrafficTreatment.
                        builder()
                        .setOutput(dst.location().port())
                        .build();
                DefaultFlowRule flowRule;
                flowRule = (DefaultFlowRule) DefaultFlowRule.builder()
                        .withPriority(policy.getPriority())
                        .withIdleTimeout(flowTimeout)
                        .forDevice(dst.location().deviceId())
                        .withSelector(builderSelector.build())
                        .withTreatment(treatment)
                        .fromApp(appId)
                        .forTable(TABLE_ID)
                        .build();
                flowRuleService.applyFlowRules(flowRule);
                policyService.addFlowRule(policy, flowRule);

            }

            forwardPacketToDst(context, dst.location());
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
            int priority = policy.getPriority();
            Link lastLink = pathLinks.get(pathLinks.size() - 1);
            Link firstLink = pathLinks.get(0);
            for (Link link : pathLinks) {
                builderSelector = policyParser.intraBuildTrafficSelector(pkt,
                        ethPkt,
                        link,
                        policy);
                if (builderSelector != null) {
                    treatment = DefaultTrafficTreatment.
                            builder()
                            .setOutput(link.src().port())
                            .build();
                    DefaultFlowRule flowRule;
                    flowRule = (DefaultFlowRule) DefaultFlowRule.builder()
                            .withPriority(priority)
                            .withIdleTimeout(flowTimeout)
                            .forDevice(link.src().deviceId())
                            .withSelector(builderSelector.build())
                            .withTreatment(treatment)
                            .fromApp(appId)
                            .forTable(TABLE_ID)
                            .build();

                    log.info(flowRule.toString());
                    flowRuleService.applyFlowRules(flowRule);
                    policyService.addFlowRule(policy, flowRule);
                    if (lastLink.equals(link)) {
                        treatment = DefaultTrafficTreatment.
                                builder()
                                .setOutput(dst.location().port())
                                .build();
                        flowRule = (DefaultFlowRule) DefaultFlowRule.builder()
                                .withPriority(priority)
                                .withIdleTimeout(flowTimeout)
                                .forDevice(dst.location().deviceId())
                                .withSelector(builderSelector.build())
                                .withTreatment(treatment)
                                .fromApp(appId)
                                .forTable(TABLE_ID)
                                .build();

                        flowRuleService.applyFlowRules(flowRule);
                        policyService.addFlowRule(policy, flowRule);

                    }
                }
            }


            forwardPacketToDst(context, firstLink.src());


        }

    }


}

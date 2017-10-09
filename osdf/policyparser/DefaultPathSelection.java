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

package org.onosproject.incubator.net.osdf.policyparser;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.UDP;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicy;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DefaultPath;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyGraph;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.topology.TopologyVertex;
import org.slf4j.Logger;

import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import static org.slf4j.LoggerFactory.getLogger;


/**
 * A default implementation of path selection algorithms.
 */
@Component(immediate = true)
@Service
public class DefaultPathSelection
        extends AbstractPathSelection
        implements PathSelectionInterface {

    private final Logger log = getLogger(getClass());
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;
    private PathSelectionAlgos pathSelectionAlgo;

    @Activate
    public void activate() {
        log.info("Started");

    }

    @Deactivate
    public void deactivate() {
        log.info("Stopped");

    }

    /**
     * Returns the path selection algorithm based on its name.
     *
     * @param pathSelectionAlgo name of path selection algorithm
     * @return Path selection algorithm.
     */
    public PathSelectionAlgos getPathSelectionAlgo(String pathSelectionAlgo) {
        switch (pathSelectionAlgo) {
            case "ECMP":
                this.pathSelectionAlgo = PathSelectionAlgos.ECMP;
                break;
            case "RANDOM":
                this.pathSelectionAlgo = PathSelectionAlgos.RANDOM;
                break;
            case "BEST_POSSIBLE_PATH":
                this.pathSelectionAlgo = PathSelectionAlgos.BEST_POSSIBLE_PATH;
                break;
            case "ON_DEMAND":
                this.pathSelectionAlgo = PathSelectionAlgos.ON_DEMAND;
                break;
            default:
                this.pathSelectionAlgo = PathSelectionAlgos.BEST_POSSIBLE_PATH;
                break;

        }

        return this.pathSelectionAlgo;


    }


    /**
     * Picks a random path based on a set of shortest path.
     *
     * @param paths  a set of paths.
     * @param policy a policy.
     * @return A path.
     */
    public Path pickRandomPath(Set<Path> paths, DefaultPolicy policy) {
        Path selectedPath = null;
        Random rnd = new Random();
        int item = 0;
        if (!paths.isEmpty()) {
            item = rnd.nextInt(paths.size());

        }
        int i = 0;

        for (Path path : paths) {

            selectedPath = path;
            if (i == item) {
                return selectedPath;
            }
            i++;

        }
        return selectedPath;


    }

    /**
     * pick a path based on ECMP algorithm.
     *
     * @param paths  paths list
     * @param policy policy
     * @param pkt    Inbound packet
     * @return a path
     */
    public Path pickEcmpBasedPath(List<Path> paths, DefaultPolicy policy, InboundPacket pkt) {
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
        IpAddress dstIp =
                IpAddress.valueOf(ipv4Packet.getDestinationAddress());
        IpAddress srcIp =
                IpAddress.valueOf(ipv4Packet.getSourceAddress());

        byte ipv4Protocol = ipv4Packet.getProtocol();
        int srcPort = 0;
        int dstPort = 0;
        if (ipv4Protocol == IPv4.PROTOCOL_TCP) {
            TCP tcpPacket = (TCP) ipv4Packet.getPayload();
            srcPort = tcpPacket.getSourcePort();
            dstPort = tcpPacket.getDestinationPort();


        } else if (ipv4Protocol == IPv4.PROTOCOL_UDP) {
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            srcPort = udpPacket.getSourcePort();
            dstPort = udpPacket.getDestinationPort();

        }

        int result = srcIp.hashCode() + dstIp.hashCode() + srcPort + dstPort;

        return paths.get(result % paths.size());

    }

    /**
     * Returns best possible path based on a set of shortest path.
     *
     * @param paths     a set of paths.
     * @param notToPort not to port
     * @param policy    a policy
     * @return a path
     */
    public Path pickBestPossiblePath(Set<Path> paths, PortNumber notToPort, DefaultPolicy policy) {
        Path selectedPath = null;

        for (Path path : paths) {

            selectedPath = path;
            if (!path.src().port().equals(notToPort)) {

                return path;
            }

        }
        return selectedPath;
    }

    /**
     * <p>
     * Returns a path on demand based on constraints which are specified in
     * a given policy.
     *
     * @param paths        paths
     * @param notToPort    not to port
     * @param policy       a policy
     * @param endToEndPath end to end path
     * @return a path
     */
    public Path pickPathOnDemand(Set<Path> paths,
                                 PortNumber notToPort,
                                 DefaultPolicy policy,
                                 DefaultPath endToEndPath) {
        Path selectedPath = null;

        boolean deviceExistance = true;

        List<Link> endPathLinks = endToEndPath.links();
        //log.debug("End path links" + endPathLinks.toString());

        List<Link> pathLinks = null;

        for (Path path : paths) {

            pathLinks = path.links();
            //log.debug("Path links ==>" + pathLinks.toString());
            if (endPathLinks.containsAll(pathLinks)) {
                selectedPath = path;
                if (!path.src().port().equals(notToPort)) {

                    log.debug("Selected path after packet" + selectedPath);
                    return path;
                }
            }


        }

        return selectedPath;


    }


    /**
     * Returns an end to end path based on constraints in a given policy.
     *
     * @param endToEndPaths end to end paths
     * @param policy        a policy
     * @return a path
     */
    public Path getEndtoEndPath(Set<Path> endToEndPaths, DefaultPolicy policy) {

        List<ConnectPoint> connectPointList;
        connectPointList = policy.getDeviceList();


        Set<ConnectPoint> pathDeviceIdSet = new HashSet<>();
        Path selectedEndPath = null;
        for (Path endToEndPath : endToEndPaths) {
            selectedEndPath = endToEndPath;
            for (Link link : endToEndPath.links()) {
                pathDeviceIdSet.add(link.src());
                pathDeviceIdSet.add(link.dst());

            }
            if (pathDeviceIdSet.containsAll(connectPointList)) {
                selectedEndPath = endToEndPath;
                break;

            }


        }

        //log.info("Selected path " + SelectedEndPath.toString());
        return selectedEndPath;
    }

    /**
     * Returns all possible paths.
     *
     * @param currentTopology current topology
     * @param srcDeviceId     source device ID
     * @param dstDeviceId     dst device ID
     * @return a set of paths
     */

    public Set<Path> getAllPaths(Topology currentTopology,
                                 DeviceId srcDeviceId,
                                 DeviceId dstDeviceId) {
        Set<Path> allPossiblePaths = new HashSet<>();
        TopologyVertex srcVertex;
        TopologyVertex dstVertex;
        TopologyGraph topologyGraph = topologyService.getGraph(currentTopology);
        return allPossiblePaths;

    }

}

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


}

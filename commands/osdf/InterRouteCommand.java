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

package org.onosproject.cli.net.osdf;

import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.incubator.net.osdf.abstractactions.ActionList;
import org.onosproject.incubator.net.osdf.policies.CreatePolicyInterface;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicy;
import org.onosproject.incubator.net.osdf.policyparser.PathSelectionAlgos;
import org.onosproject.incubator.net.osdf.policyparser.PathSelectionInterface;
import org.onosproject.incubator.net.osdf.policystorage.PolicyService;
import org.onosproject.incubator.net.osdf.policystorage.PolicyState;
import org.onosproject.incubator.net.osdf.trafficprofiles.CreateTrafficProfile;
import org.onosproject.incubator.net.osdf.trafficprofiles.DefaultTrafficProfile;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.HostId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.region.RegionId;
import org.onosproject.net.region.RegionService;

import java.util.ArrayList;
import java.util.List;

/**
 * Inter-route command.
 */


@Command(scope = "onos", name = "Inter-route",
        description = "route packets based on high level network information between regions")
public class InterRouteCommand extends AbstractShellCommand {


    private static final int DEFAULT_PRIORITY = 50;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;
    private DefaultPolicy policy;
    @Argument(index = 0, name = "profileName", description = "ProfileName",
            required = true, multiValued = false)
    private String profileName = null;
    @Option(name = "-a", aliases = "--app", description = "Application type",
            required = false, multiValued = false)
    private String appType = null;
    @Option(name = "-p", aliases = "--priority", description = "Priority",
            required = false, multiValued = false)
    private String priority = null;
    @Option(name = "-via", aliases = "--via", description = "partial path",
            required = false, multiValued = false)
    private String path = null;
    @Option(name = "-psa", aliases = "--pathSelection", description = "Path selection algorithm",
            required = false, multiValued = false)
    private String pathSelectionAlgoString = null;
    @Option(name = "-srcRegion", aliases = "--srcRegion", description = "source region",
            required = true, multiValued = false)
    private String srcRegionID = null;
    @Option(name = "-dstRegion", aliases = "--dstRegion", description = "destination region",
            required = true, multiValued = false)
    private String dstRegionID = null;
    @Option(name = "-sh", aliases = "--source hosts", description = "A list of source hosts",
            required = false, multiValued = false)
    private String srcHosts = null;
    @Option(name = "-dh", aliases = "--destination hosts", description = "A list of destination hosts",
            required = false, multiValued = false)
    private String dstHosts = null;


    @Override
    protected void execute() {


        CreateTrafficProfile createTrafficProfile;
        DefaultTrafficProfile trafficProfile;

        RegionService regionService = get(RegionService.class);
        RegionId srcRegionId = RegionId.regionId(srcRegionID);
        RegionId dstRegionId = RegionId.regionId(dstRegionID);

        PathSelectionInterface pathSelection;
        pathSelection = get(PathSelectionInterface.class);

        CreatePolicyInterface createPolicy;

        PolicyService policyService;
        policyService = get(PolicyService.class);


        createPolicy = get(CreatePolicyInterface.class);
        createTrafficProfile = get(CreateTrafficProfile.class);


        createTrafficProfile.createTrafficProfile(appType, profileName);
        trafficProfile = (DefaultTrafficProfile) createTrafficProfile.getTrafficProfile();

        PathSelectionAlgos pathSelectionAlgo;

        if (pathSelectionAlgoString != null) {

            pathSelectionAlgo = pathSelection.getPathSelectionAlgo(pathSelectionAlgoString);

        } else {
            pathSelectionAlgo = PathSelectionAlgos.BEST_POSSIBLE_PATH;

        }

        String[] tokens = null;
        List<ConnectPoint> deviceList = new ArrayList<>();

        List<HostId> srcHostsList = new ArrayList<HostId>();
        List<HostId> dstHostsList = new ArrayList<HostId>();

        if (path != null) {

            try {
                tokens = path.split(",");
            } catch (NullPointerException e) {

            }

            if (tokens.length != 0) {
                for (String token : tokens) {


                    deviceList.add(ConnectPoint.deviceConnectPoint(token));
                }
            } else {
                deviceList.add(ConnectPoint.deviceConnectPoint(path));
            }

        }

        if (srcHosts != null) {

            try {
                tokens = srcHosts.split(",");
            } catch (NullPointerException e) {

            }

            if (tokens.length != 0) {
                for (String token : tokens) {

                    srcHostsList.add(HostId.hostId(token));
                }
            }

        }

        if (dstHosts != null) {

            try {
                tokens = dstHosts.split(",");
            } catch (NullPointerException e) {

            }

            if (tokens.length != 0) {
                for (String token : tokens) {

                    dstHostsList.add(HostId.hostId(token));
                }
            }

        }


        if (priority == null) {
            priority = String.valueOf(DEFAULT_PRIORITY);
        }


        createPolicy.createPolicy(appType + ":" + profileName,
                Integer.parseInt(priority),
                PolicyState.INSTALL_REQ,
                1,
                deviceList,
                srcHostsList,
                dstHostsList,
                pathSelectionAlgo,
                trafficProfile,
                regionService.getRegion(srcRegionId),
                regionService.getRegion(dstRegionId),
                ActionList.INTER_ROUTE);


        policy = (DefaultPolicy) createPolicy.getPolicy();
        log.info(policy.getDeviceList().toString());
        policyService.addCurrent(policy);
        //policyConflictsMgmtsService.conflictDection();


    }
}

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

package org.onosproject.incubator.net.osdf.policies;


import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.incubator.net.osdf.abstractactions.ActionList;
import org.onosproject.incubator.net.osdf.policyparser.PathSelectionAlgos;
import org.onosproject.incubator.net.osdf.policystorage.PolicyState;
import org.onosproject.incubator.net.osdf.trafficprofiles.DefaultTrafficProfile;
import org.onosproject.incubator.net.osdf.trafficprofiles.TrafficProfile;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.HostId;
import org.onosproject.net.region.Region;

import java.util.List;
import java.util.logging.Logger;

/**
 * An implementation of CreatePolicy Interface.
 */

@Component(immediate = true)
@Service
public class DefaultCreatePolicy
        extends AbstractCreatePolicy
        implements CreatePolicyInterface {

    private final Logger log = Logger.getLogger(getClass().getName());
    DefaultPolicy policy;


    @Activate
    public void activate() {
        log.info("Started");
        policy = null;


    }


    @Deactivate
    public void deactivate() {

        log.info("Stopped");
    }

    /**
     * Creates a high level network policy based on given information
     * including policy name, traffic profile, partial path information,
     * source and destination regions.
     *
     * @param policyName        policy name
     * @param priority          priority
     * @param policyState       policy state
     * @param version           policy version
     * @param connectPointList  List of connection points
     * @param srcHostsList      source hosts list
     * @param dstHostsList      dst hosts list
     * @param pathSelectionAlgo path selection algorithm
     * @param trafficProfile    traffic profile
     * @param srcRegion         source region
     * @param dstRegion         dst region
     * @param action            action
     */
    public void createPolicy(String policyName,
                             int priority,
                             PolicyState policyState,
                             int version,
                             List<ConnectPoint> connectPointList,
                             List<HostId> srcHostsList,
                             List<HostId> dstHostsList,
                             PathSelectionAlgos pathSelectionAlgo,
                             TrafficProfile trafficProfile,
                             Region srcRegion,
                             Region dstRegion,
                             ActionList action) {

        DefaultPolicyId defaultPolicyId;
        defaultPolicyId = new DefaultPolicyId();
        defaultPolicyId.createPolicyId(policyName);



        policy = DefaultPolicy
                .builder()
                .policyId(defaultPolicyId)
                .priority(priority)
                .policyState(policyState)
                .version(version)
                .connectPointList(connectPointList)
                .srcHostsList(srcHostsList)
                .dstHostsList(dstHostsList)
                .pathSelectionAlgo(pathSelectionAlgo)
                .trafficProfile((DefaultTrafficProfile) trafficProfile)
                .action(action)
                .srcRegion(srcRegion)
                .dstRegion(dstRegion)
                .build();


    }


    /**
     * Returns a created policy.
     *
     * @return a policy
     */
    @Override
    public Policy getPolicy() {

        return policy;
    }

}

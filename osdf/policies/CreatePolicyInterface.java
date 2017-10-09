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

import org.onosproject.incubator.net.osdf.abstractactions.ActionList;
import org.onosproject.incubator.net.osdf.policyparser.PathSelectionAlgos;
import org.onosproject.incubator.net.osdf.policystorage.PolicyState;
import org.onosproject.incubator.net.osdf.trafficprofiles.TrafficProfile;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.HostId;
import org.onosproject.net.region.Region;

import java.util.List;

/**
 * Creating high level network policies interface.
 */
public interface CreatePolicyInterface {

    /**
     * * <p>
     * Creates a high level network policy based on given information
     * including policy name, traffic profile, partial path information,
     * source and destination regions.
     *
     * @param policyName        policy name
     * @param priority          policy priority
     * @param policyState       policy state
     * @param version           policy version
     * @param connectPointList  connection points list
     * @param srcHostsList      source hosts list
     * @param dstHostsList      dst hosts list
     * @param pathSelectionAlgo path selection algorithm
     * @param trafficProfile    traffic profile
     * @param srcRegion         source region
     * @param dstRegion         dst region
     * @param action            action.
     */
    void createPolicy(String policyName,
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
                      ActionList action);


    /**
     *
     * @param policyName
     * @param priority
     * @param policyState
     * @param version
     * @param connectPointList
     * @param srcHostsList
     * @param dstHostsList
     * @param pathSelectionAlgo
     * @param trafficProfile
     * @param srcRegion
     * @param dstRegion
     * @param networkServiceEntryList
     * @param rate
     * @param action
     */


    /**
     * Returns a created policy.
     *
     * @return a policy
     */


    Policy getPolicy();
}

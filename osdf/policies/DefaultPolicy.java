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
import org.onosproject.incubator.net.osdf.trafficprofiles.DefaultTrafficProfile;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.HostId;
import org.onosproject.net.region.Region;

import java.util.List;


/**
 * High level network policy representation.
 */
public class DefaultPolicy extends Policy {


    List<ConnectPoint> connectPointList;
    List<HostId> srcHostsList;
    List<HostId> dstHostsList;
    ActionList action;
    Region srcRegion;
    Region dstRegion;
    PathSelectionAlgos pathSelectionAlgo;
    private DefaultTrafficProfile trafficProfile;


    /**
     * Default Constructor.
     */

    protected DefaultPolicy() {
        super();
        this.trafficProfile = null;
        connectPointList = null;
        srcHostsList = null;
        dstHostsList = null;
        action = null;
        pathSelectionAlgo = null;
        srcRegion = null;
        dstRegion = null;


    }

    /**
     * <p>
     * * Creates a high level network policy based on given information
     * including policy name, traffic profile, partial path information,
     * source and destination regions.
     *
     * @param policyId          policy id
     * @param priority          policy priority
     * @param policyState       policy state
     * @param version           policy version
     * @param devices           network devices
     * @param srcHosts          source hosts list
     * @param dstHosts          destination hosts list
     * @param pathSelectionAlgo path selection algorithm
     * @param trafficProfile    traffic profile
     * @param srcRegion         source region
     * @param dstRegion         destination region
     * @param action            abstract action
     */
    protected DefaultPolicy(DefaultPolicyId policyId,
                            int priority,
                            PolicyState policyState,
                            int version,
                            List<ConnectPoint> devices,
                            List<HostId> srcHosts,
                            List<HostId> dstHosts,
                            PathSelectionAlgos pathSelectionAlgo,
                            DefaultTrafficProfile trafficProfile,
                            Region srcRegion,
                            Region dstRegion,
                            ActionList action) {

        super(policyId, priority, policyState, version);
        this.trafficProfile = trafficProfile;
        this.connectPointList = devices;
        this.action = action;
        this.srcHostsList = srcHosts;
        this.dstHostsList = dstHosts;
        this.pathSelectionAlgo = pathSelectionAlgo;
        this.srcRegion = srcRegion;
        this.dstRegion = dstRegion;


    }

    /**
     * Return a Builder object.
     *
     * @return a builder object
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns a policy builder.
     *
     * @param policy a policy
     * @return policy builder
     */
    public static Builder builder(DefaultPolicy policy) {
        return new Builder(policy);
    }


    /**
     * Return a traffic profile.
     *
     * @return trafficProfile
     */
    public DefaultTrafficProfile getTrafficProfile() {
        return trafficProfile;
    }

    /**
     * Returns the action of a policy.
     *
     * @return abstract action
     */
    public ActionList getAction() {
        return action;
    }

    /**
     * Returns a list of connection points which specified in a policy.
     *
     * @return A list of connection points
     */
    public List<ConnectPoint> getDeviceList() {
        return connectPointList;
    }


    /**
     * Returns a list of source hosts which specified in a policy.
     *
     * @return a List of source hosts
     */
    public List<HostId> getSrcHostsList() {
        return srcHostsList;
    }

    /**
     * Returns a list of destination hosts which specified in a policy.
     *
     * @return a list of dst hosts
     */
    public List<HostId> getDstHostsList() {
        return dstHostsList;
    }

    /**
     * Returns the path selection algorithm method.
     *
     * @return path selection algorithm ID
     */
    public PathSelectionAlgos getPathSelectionAlgo() {
        return pathSelectionAlgo;
    }

    /**
     * Returns the source region of a given policy.
     *
     * @return source region
     */
    public Region getSrcRegion() {
        return srcRegion;
    }

    /**
     * Returns the destination region of a given policy.
     *
     * @return destination region
     */
    public Region getDstRegion() {
        return dstRegion;
    }


    /**
     *
     */
    public static class Builder extends Policy.Builder {

        protected DefaultTrafficProfile trafficProfile;
        protected List<ConnectPoint> connectPointList;
        protected List<HostId> srcHostsList;
        protected List<HostId> dstHostsList;
        protected ActionList action;
        protected PathSelectionAlgos pathSelectionAlgo;
        protected Region srcRegion;
        protected Region dstRegion;


        /**
         * creates an empty Builder.
         */
        public Builder() {


        }

        public Builder(DefaultPolicy policy) {
            this.priority = policy.getPriority();
            this.trafficProfile = policy.getTrafficProfile();
            this.pathSelectionAlgo = policy.getPathSelectionAlgo();
            this.srcRegion = policy.getSrcRegion();
            this.dstRegion = policy.getDstRegion();
            this.policyId = (DefaultPolicyId) policy.getPolicyId();
            this.policyState = policy.getPolicyState();
            this.connectPointList = policy.getDeviceList();
            this.srcHostsList = policy.getSrcHostsList();
            this.dstHostsList = policy.getDstHostsList();
            this.action = policy.getAction();


        }


        /**
         * Sets the policy id for the policy.
         *
         * @param policyId policy identifier
         * @return this builder
         */
        @Override
        public Builder policyId(DefaultPolicyId policyId) {
            return (Builder) super.policyId(policyId);
        }


        /**
         * Sets the priority of for a policy.
         *
         * @param priority policy priority
         * @return this builder
         */
        @Override
        public Builder priority(int priority) {
            return (Builder) super.priority(priority);
        }


        /**
         * Sets the policy state.
         *
         * @param policyState policy state
         * @return this builder
         */
        @Override
        public Builder policyState(PolicyState policyState) {
            return (Builder) super.policyState(policyState);
        }

        /**
         * Sets the version for a policy.
         *
         * @param version policy version
         * @return policy version
         */
        @Override
        public Builder version(int version) {
            return (Builder) super.version(version);
        }


        /**
         * Sets a traffic profile for the policy.
         *
         * @param trafficProfile a network traffic profile
         * @return this builder
         */
        public Builder trafficProfile(DefaultTrafficProfile trafficProfile) {
            this.trafficProfile = trafficProfile;
            return this;
        }

        /**
         * Sets connection points list for the policy.
         *
         * @param connectPointList connection points list
         * @return this builder
         */
        public Builder connectPointList(List<ConnectPoint> connectPointList) {
            this.connectPointList = connectPointList;
            return this;
        }

        /**
         * Sets an action for the policy.
         *
         * @param action action
         * @return this builder
         */
        public Builder action(ActionList action) {
            this.action = action;
            return this;
        }

        /**
         * Sets a list of hosts for the policy.
         *
         * @param srcHostsList source hosts list
         * @return this builder
         */
        public Builder srcHostsList(List<HostId> srcHostsList) {
            this.srcHostsList = srcHostsList;
            return this;
        }

        /**
         * @param dstHostsList dst hosts list
         * @return this builder
         */
        public Builder dstHostsList(List<HostId> dstHostsList) {
            this.dstHostsList = dstHostsList;
            return this;
        }


        /**
         * Set a path selection algorithm for the policy.
         *
         * @param pathSelectionAlgo path selection algorithm
         * @return this builder
         */
        public Builder pathSelectionAlgo(PathSelectionAlgos pathSelectionAlgo) {
            this.pathSelectionAlgo = pathSelectionAlgo;
            return this;
        }

        /**
         * Sets a source region for the policy.
         *
         * @param srcRegion source region
         * @return this builder
         */
        public Builder srcRegion(Region srcRegion) {
            this.srcRegion = srcRegion;
            return this;
        }

        /**
         * Sets a destination region for the policy.
         *
         * @param dstRegion dst region
         * @return this builder
         */
        public Builder dstRegion(Region dstRegion) {
            this.dstRegion = dstRegion;
            return this;
        }


        /**
         * policy builder.
         *
         * @return a policy
         */
        public DefaultPolicy build() {

            return new DefaultPolicy(policyId,
                    priority,
                    policyState,
                    version,
                    connectPointList,
                    srcHostsList,
                    dstHostsList,
                    pathSelectionAlgo,
                    trafficProfile,
                    srcRegion,
                    dstRegion,
                    action);
        }

    }


}

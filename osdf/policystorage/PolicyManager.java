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

package org.onosproject.incubator.net.osdf.policystorage;

import com.google.common.collect.Multimap;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.event.AbstractListenerManager;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicyId;
import org.onosproject.incubator.net.osdf.policies.Policy;
import org.onosproject.net.flow.DefaultFlowRule;
import org.slf4j.Logger;

import java.util.Collection;
import java.util.Map;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Policy Manager which handles storing and retrieving network policies.
 */
@Component(immediate = true)
@Service
public class PolicyManager extends
        AbstractListenerManager<PolicyEvent, PolicyListener> implements PolicyService {


    private static final Logger log = getLogger(PolicyManager.class);
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private PolicyStore policyStore;
    private PolicyStoreDelegate delegate = new InternalStoreDelegate();

    @Activate
    public void activate() {
        log.info("Started");
        policyStore.setDelegate(delegate);
        eventDispatcher.addSink(PolicyEvent.class, listenerRegistry);

    }

    @Deactivate
    public void deactivate() {
        log.info("Stopped");
        policyStore.unsetDelegate(delegate);
        eventDispatcher.removeSink(PolicyEvent.class);

    }


    @Override
    public Iterable<Policy> getPolicies() {
        return policyStore.getPolicies();
    }

    @Override
    public void addPending(Policy policy) {
        policyStore.addPending(policy);


    }

    @Override
    public Iterable<Policy> getPendingPolicies() {
        return policyStore.getPendingPolicies();
    }

    @Override
    public void addCurrent(Policy policy) {
        policyStore.addCurrent(policy);

    }

    @Override
    public Iterable<Policy> getCurrentPolicies() {
        return policyStore.getCurrentPolicies();
    }

    @Override
    public void addFlowRule(Policy policy, DefaultFlowRule flowRule) {
        policyStore.addFlowRule(policy, flowRule);

    }

    @Override
    public void removeCurrentPolicy(Policy policy) {

        policyStore.removeCurrentPolicy(policy);
    }

    @Override
    public Policy getPolicy(String policyId) {
        return policyStore.getPolicy(policyId);
    }

    @Override
    public Map<DefaultPolicyId, Policy> getCurrentPolicyMap() {
        return policyStore.getCurrentPolicyMap();
    }

    @Override
    public int getRulesCount(Policy policy) {
        return policyStore.getRulesCount(policy);


    }

    @Override
    public Multimap<DefaultPolicyId, DefaultFlowRule> getFlowRulesList() {
        return policyStore.getFlowRulesList();
    }

    @Override
    public Collection<DefaultFlowRule> getFlowRulesForPolicy(Policy policy) {
        return policyStore.getFlowRulesForPolicy(policy);
    }

    // Store delegate to re-post events emitted from the store.
    public class InternalStoreDelegate implements PolicyStoreDelegate {
        @Override
        public void notify(PolicyEvent event) {
            post(event);
        }

    }
}

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

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicy;
import org.onosproject.incubator.net.osdf.policies.Policy;
import org.onosproject.incubator.net.osdf.policystorage.PolicyEvent;
import org.onosproject.incubator.net.osdf.policystorage.PolicyListener;
import org.onosproject.incubator.net.osdf.policystorage.PolicyService;
import org.slf4j.Logger;

import java.util.Iterator;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Remove policy command.
 */
@Command(scope = "onos", name = "remove-policy",
        description = "Remove a policy from the list of current active policies")
public class RemovePolicyCommand extends AbstractShellCommand {

    //@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    //protected PolicyService policyService;

    @Argument(index = 0, name = "policyID", description = "PolicyID",
            required = true, multiValued = false)
    private String policyID = null;

    private final Logger log = getLogger(getClass());

    @Override
    protected void execute() {

        PolicyService policyService;
        policyService = get(PolicyService.class);
        PolicyListener policyListener = new InnerPolicyListener();

        policyService.addListener(policyListener);
        DefaultPolicy policy = (DefaultPolicy) policyService.getPolicy(policyID);
        policyService.removeCurrentPolicy(policy);




    }

    private class InnerPolicyListener implements PolicyListener {

        @Override
        public void event(PolicyEvent event) {


            switch (event.type()) {
                case INSTALL_REQ:
                    //log.info("INSTALL REQ");
                    break;
                default:
                    //log.info("No policy event");
                    break;
            }
        }
    }


}

#H2 Overview

Using SDN to configure and control a multi-site network involves writing code that handles low-level details. We designed and implemented a prelimanry framework that takes a network description and set of policies as input, and handles all the details of deriving routes and installing flow rules in switches. The main design goals of the framework are explained as follows:

1. Provide a high level interface that allows managers to express policies and, when needed, allows programmers to write network management applications without worrying about the low-level details of how the information is transported and stored, and without writing code that parses data obtained from a device.
    
2. Predefine a set of high level network services that can be invoked by management applications to configure a switch without knowing the details of the southbound API (e.g., OpenFlow or an alternative).
    
3. Devise a system that can run management applications analogous to the way a conventional operating system runs processes. Just as a conventional process uses services provided by its operating system, a network management application will use services provided by our system.
    
4. Design and develop a hybrid approach that allows programmers to specify network configurations both proactively, by deriving configuration rules from high-level network policies, and reactively, by modifying the configuration as flows and conditions change.


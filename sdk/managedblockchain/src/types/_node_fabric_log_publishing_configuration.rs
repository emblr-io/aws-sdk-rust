// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration properties for logging events associated with a peer node owned by a member in a Managed Blockchain network.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NodeFabricLogPublishingConfiguration {
    /// <p>Configuration properties for logging events associated with chaincode execution on a peer node. Chaincode logs contain the results of instantiating, invoking, and querying the chaincode. A peer can run multiple instances of chaincode. When enabled, a log stream is created for all chaincodes, with an individual log stream for each chaincode.</p>
    pub chaincode_logs: ::std::option::Option<crate::types::LogConfigurations>,
    /// <p>Configuration properties for a peer node log. Peer node logs contain messages generated when your client submits transaction proposals to peer nodes, requests to join channels, enrolls an admin peer, and lists the chaincode instances on a peer node.</p>
    pub peer_logs: ::std::option::Option<crate::types::LogConfigurations>,
}
impl NodeFabricLogPublishingConfiguration {
    /// <p>Configuration properties for logging events associated with chaincode execution on a peer node. Chaincode logs contain the results of instantiating, invoking, and querying the chaincode. A peer can run multiple instances of chaincode. When enabled, a log stream is created for all chaincodes, with an individual log stream for each chaincode.</p>
    pub fn chaincode_logs(&self) -> ::std::option::Option<&crate::types::LogConfigurations> {
        self.chaincode_logs.as_ref()
    }
    /// <p>Configuration properties for a peer node log. Peer node logs contain messages generated when your client submits transaction proposals to peer nodes, requests to join channels, enrolls an admin peer, and lists the chaincode instances on a peer node.</p>
    pub fn peer_logs(&self) -> ::std::option::Option<&crate::types::LogConfigurations> {
        self.peer_logs.as_ref()
    }
}
impl NodeFabricLogPublishingConfiguration {
    /// Creates a new builder-style object to manufacture [`NodeFabricLogPublishingConfiguration`](crate::types::NodeFabricLogPublishingConfiguration).
    pub fn builder() -> crate::types::builders::NodeFabricLogPublishingConfigurationBuilder {
        crate::types::builders::NodeFabricLogPublishingConfigurationBuilder::default()
    }
}

/// A builder for [`NodeFabricLogPublishingConfiguration`](crate::types::NodeFabricLogPublishingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NodeFabricLogPublishingConfigurationBuilder {
    pub(crate) chaincode_logs: ::std::option::Option<crate::types::LogConfigurations>,
    pub(crate) peer_logs: ::std::option::Option<crate::types::LogConfigurations>,
}
impl NodeFabricLogPublishingConfigurationBuilder {
    /// <p>Configuration properties for logging events associated with chaincode execution on a peer node. Chaincode logs contain the results of instantiating, invoking, and querying the chaincode. A peer can run multiple instances of chaincode. When enabled, a log stream is created for all chaincodes, with an individual log stream for each chaincode.</p>
    pub fn chaincode_logs(mut self, input: crate::types::LogConfigurations) -> Self {
        self.chaincode_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration properties for logging events associated with chaincode execution on a peer node. Chaincode logs contain the results of instantiating, invoking, and querying the chaincode. A peer can run multiple instances of chaincode. When enabled, a log stream is created for all chaincodes, with an individual log stream for each chaincode.</p>
    pub fn set_chaincode_logs(mut self, input: ::std::option::Option<crate::types::LogConfigurations>) -> Self {
        self.chaincode_logs = input;
        self
    }
    /// <p>Configuration properties for logging events associated with chaincode execution on a peer node. Chaincode logs contain the results of instantiating, invoking, and querying the chaincode. A peer can run multiple instances of chaincode. When enabled, a log stream is created for all chaincodes, with an individual log stream for each chaincode.</p>
    pub fn get_chaincode_logs(&self) -> &::std::option::Option<crate::types::LogConfigurations> {
        &self.chaincode_logs
    }
    /// <p>Configuration properties for a peer node log. Peer node logs contain messages generated when your client submits transaction proposals to peer nodes, requests to join channels, enrolls an admin peer, and lists the chaincode instances on a peer node.</p>
    pub fn peer_logs(mut self, input: crate::types::LogConfigurations) -> Self {
        self.peer_logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration properties for a peer node log. Peer node logs contain messages generated when your client submits transaction proposals to peer nodes, requests to join channels, enrolls an admin peer, and lists the chaincode instances on a peer node.</p>
    pub fn set_peer_logs(mut self, input: ::std::option::Option<crate::types::LogConfigurations>) -> Self {
        self.peer_logs = input;
        self
    }
    /// <p>Configuration properties for a peer node log. Peer node logs contain messages generated when your client submits transaction proposals to peer nodes, requests to join channels, enrolls an admin peer, and lists the chaincode instances on a peer node.</p>
    pub fn get_peer_logs(&self) -> &::std::option::Option<crate::types::LogConfigurations> {
        &self.peer_logs
    }
    /// Consumes the builder and constructs a [`NodeFabricLogPublishingConfiguration`](crate::types::NodeFabricLogPublishingConfiguration).
    pub fn build(self) -> crate::types::NodeFabricLogPublishingConfiguration {
        crate::types::NodeFabricLogPublishingConfiguration {
            chaincode_logs: self.chaincode_logs,
            peer_logs: self.peer_logs,
        }
    }
}

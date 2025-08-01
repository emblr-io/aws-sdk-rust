// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about AwsGroundStationAgentEndpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsGroundStationAgentEndpoint {
    /// <p>Name string associated with AgentEndpoint. Used as a human-readable identifier for AgentEndpoint.</p>
    pub name: ::std::string::String,
    /// <p>The egress address of AgentEndpoint.</p>
    pub egress_address: ::std::option::Option<crate::types::ConnectionDetails>,
    /// <p>The ingress address of AgentEndpoint.</p>
    pub ingress_address: ::std::option::Option<crate::types::RangedConnectionDetails>,
    /// <p>The status of AgentEndpoint.</p>
    pub agent_status: ::std::option::Option<crate::types::AgentStatus>,
    /// <p>The results of the audit.</p>
    pub audit_results: ::std::option::Option<crate::types::AuditResults>,
}
impl AwsGroundStationAgentEndpoint {
    /// <p>Name string associated with AgentEndpoint. Used as a human-readable identifier for AgentEndpoint.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The egress address of AgentEndpoint.</p>
    pub fn egress_address(&self) -> ::std::option::Option<&crate::types::ConnectionDetails> {
        self.egress_address.as_ref()
    }
    /// <p>The ingress address of AgentEndpoint.</p>
    pub fn ingress_address(&self) -> ::std::option::Option<&crate::types::RangedConnectionDetails> {
        self.ingress_address.as_ref()
    }
    /// <p>The status of AgentEndpoint.</p>
    pub fn agent_status(&self) -> ::std::option::Option<&crate::types::AgentStatus> {
        self.agent_status.as_ref()
    }
    /// <p>The results of the audit.</p>
    pub fn audit_results(&self) -> ::std::option::Option<&crate::types::AuditResults> {
        self.audit_results.as_ref()
    }
}
impl AwsGroundStationAgentEndpoint {
    /// Creates a new builder-style object to manufacture [`AwsGroundStationAgentEndpoint`](crate::types::AwsGroundStationAgentEndpoint).
    pub fn builder() -> crate::types::builders::AwsGroundStationAgentEndpointBuilder {
        crate::types::builders::AwsGroundStationAgentEndpointBuilder::default()
    }
}

/// A builder for [`AwsGroundStationAgentEndpoint`](crate::types::AwsGroundStationAgentEndpoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsGroundStationAgentEndpointBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) egress_address: ::std::option::Option<crate::types::ConnectionDetails>,
    pub(crate) ingress_address: ::std::option::Option<crate::types::RangedConnectionDetails>,
    pub(crate) agent_status: ::std::option::Option<crate::types::AgentStatus>,
    pub(crate) audit_results: ::std::option::Option<crate::types::AuditResults>,
}
impl AwsGroundStationAgentEndpointBuilder {
    /// <p>Name string associated with AgentEndpoint. Used as a human-readable identifier for AgentEndpoint.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name string associated with AgentEndpoint. Used as a human-readable identifier for AgentEndpoint.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name string associated with AgentEndpoint. Used as a human-readable identifier for AgentEndpoint.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The egress address of AgentEndpoint.</p>
    /// This field is required.
    pub fn egress_address(mut self, input: crate::types::ConnectionDetails) -> Self {
        self.egress_address = ::std::option::Option::Some(input);
        self
    }
    /// <p>The egress address of AgentEndpoint.</p>
    pub fn set_egress_address(mut self, input: ::std::option::Option<crate::types::ConnectionDetails>) -> Self {
        self.egress_address = input;
        self
    }
    /// <p>The egress address of AgentEndpoint.</p>
    pub fn get_egress_address(&self) -> &::std::option::Option<crate::types::ConnectionDetails> {
        &self.egress_address
    }
    /// <p>The ingress address of AgentEndpoint.</p>
    /// This field is required.
    pub fn ingress_address(mut self, input: crate::types::RangedConnectionDetails) -> Self {
        self.ingress_address = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ingress address of AgentEndpoint.</p>
    pub fn set_ingress_address(mut self, input: ::std::option::Option<crate::types::RangedConnectionDetails>) -> Self {
        self.ingress_address = input;
        self
    }
    /// <p>The ingress address of AgentEndpoint.</p>
    pub fn get_ingress_address(&self) -> &::std::option::Option<crate::types::RangedConnectionDetails> {
        &self.ingress_address
    }
    /// <p>The status of AgentEndpoint.</p>
    pub fn agent_status(mut self, input: crate::types::AgentStatus) -> Self {
        self.agent_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of AgentEndpoint.</p>
    pub fn set_agent_status(mut self, input: ::std::option::Option<crate::types::AgentStatus>) -> Self {
        self.agent_status = input;
        self
    }
    /// <p>The status of AgentEndpoint.</p>
    pub fn get_agent_status(&self) -> &::std::option::Option<crate::types::AgentStatus> {
        &self.agent_status
    }
    /// <p>The results of the audit.</p>
    pub fn audit_results(mut self, input: crate::types::AuditResults) -> Self {
        self.audit_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The results of the audit.</p>
    pub fn set_audit_results(mut self, input: ::std::option::Option<crate::types::AuditResults>) -> Self {
        self.audit_results = input;
        self
    }
    /// <p>The results of the audit.</p>
    pub fn get_audit_results(&self) -> &::std::option::Option<crate::types::AuditResults> {
        &self.audit_results
    }
    /// Consumes the builder and constructs a [`AwsGroundStationAgentEndpoint`](crate::types::AwsGroundStationAgentEndpoint).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::AwsGroundStationAgentEndpointBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::AwsGroundStationAgentEndpoint, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AwsGroundStationAgentEndpoint {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AwsGroundStationAgentEndpoint",
                )
            })?,
            egress_address: self.egress_address,
            ingress_address: self.ingress_address,
            agent_status: self.agent_status,
            audit_results: self.audit_results,
        })
    }
}

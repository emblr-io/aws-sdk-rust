// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateEndpointInput {
    /// <p>The name of the endpoint you want to update.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description for the endpoint.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Configure the routing policy, including the health check and secondary Region.</p>
    pub routing_config: ::std::option::Option<crate::types::RoutingConfig>,
    /// <p>Whether event replication was enabled or disabled by this request.</p>
    pub replication_config: ::std::option::Option<crate::types::ReplicationConfig>,
    /// <p>Define event buses used for replication.</p>
    pub event_buses: ::std::option::Option<::std::vec::Vec<crate::types::EndpointEventBus>>,
    /// <p>The ARN of the role used by event replication for this request.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateEndpointInput {
    /// <p>The name of the endpoint you want to update.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description for the endpoint.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Configure the routing policy, including the health check and secondary Region.</p>
    pub fn routing_config(&self) -> ::std::option::Option<&crate::types::RoutingConfig> {
        self.routing_config.as_ref()
    }
    /// <p>Whether event replication was enabled or disabled by this request.</p>
    pub fn replication_config(&self) -> ::std::option::Option<&crate::types::ReplicationConfig> {
        self.replication_config.as_ref()
    }
    /// <p>Define event buses used for replication.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.event_buses.is_none()`.
    pub fn event_buses(&self) -> &[crate::types::EndpointEventBus] {
        self.event_buses.as_deref().unwrap_or_default()
    }
    /// <p>The ARN of the role used by event replication for this request.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
}
impl UpdateEndpointInput {
    /// Creates a new builder-style object to manufacture [`UpdateEndpointInput`](crate::operation::update_endpoint::UpdateEndpointInput).
    pub fn builder() -> crate::operation::update_endpoint::builders::UpdateEndpointInputBuilder {
        crate::operation::update_endpoint::builders::UpdateEndpointInputBuilder::default()
    }
}

/// A builder for [`UpdateEndpointInput`](crate::operation::update_endpoint::UpdateEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateEndpointInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) routing_config: ::std::option::Option<crate::types::RoutingConfig>,
    pub(crate) replication_config: ::std::option::Option<crate::types::ReplicationConfig>,
    pub(crate) event_buses: ::std::option::Option<::std::vec::Vec<crate::types::EndpointEventBus>>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateEndpointInputBuilder {
    /// <p>The name of the endpoint you want to update.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the endpoint you want to update.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the endpoint you want to update.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description for the endpoint.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the endpoint.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the endpoint.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Configure the routing policy, including the health check and secondary Region.</p>
    pub fn routing_config(mut self, input: crate::types::RoutingConfig) -> Self {
        self.routing_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configure the routing policy, including the health check and secondary Region.</p>
    pub fn set_routing_config(mut self, input: ::std::option::Option<crate::types::RoutingConfig>) -> Self {
        self.routing_config = input;
        self
    }
    /// <p>Configure the routing policy, including the health check and secondary Region.</p>
    pub fn get_routing_config(&self) -> &::std::option::Option<crate::types::RoutingConfig> {
        &self.routing_config
    }
    /// <p>Whether event replication was enabled or disabled by this request.</p>
    pub fn replication_config(mut self, input: crate::types::ReplicationConfig) -> Self {
        self.replication_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether event replication was enabled or disabled by this request.</p>
    pub fn set_replication_config(mut self, input: ::std::option::Option<crate::types::ReplicationConfig>) -> Self {
        self.replication_config = input;
        self
    }
    /// <p>Whether event replication was enabled or disabled by this request.</p>
    pub fn get_replication_config(&self) -> &::std::option::Option<crate::types::ReplicationConfig> {
        &self.replication_config
    }
    /// Appends an item to `event_buses`.
    ///
    /// To override the contents of this collection use [`set_event_buses`](Self::set_event_buses).
    ///
    /// <p>Define event buses used for replication.</p>
    pub fn event_buses(mut self, input: crate::types::EndpointEventBus) -> Self {
        let mut v = self.event_buses.unwrap_or_default();
        v.push(input);
        self.event_buses = ::std::option::Option::Some(v);
        self
    }
    /// <p>Define event buses used for replication.</p>
    pub fn set_event_buses(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EndpointEventBus>>) -> Self {
        self.event_buses = input;
        self
    }
    /// <p>Define event buses used for replication.</p>
    pub fn get_event_buses(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EndpointEventBus>> {
        &self.event_buses
    }
    /// <p>The ARN of the role used by event replication for this request.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the role used by event replication for this request.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The ARN of the role used by event replication for this request.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`UpdateEndpointInput`](crate::operation::update_endpoint::UpdateEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_endpoint::UpdateEndpointInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_endpoint::UpdateEndpointInput {
            name: self.name,
            description: self.description,
            routing_config: self.routing_config,
            replication_config: self.replication_config,
            event_buses: self.event_buses,
            role_arn: self.role_arn,
        })
    }
}

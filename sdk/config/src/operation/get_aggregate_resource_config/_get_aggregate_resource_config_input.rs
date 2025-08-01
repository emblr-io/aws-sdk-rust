// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAggregateResourceConfigInput {
    /// <p>The name of the configuration aggregator.</p>
    pub configuration_aggregator_name: ::std::option::Option<::std::string::String>,
    /// <p>An object that identifies aggregate resource.</p>
    pub resource_identifier: ::std::option::Option<crate::types::AggregateResourceIdentifier>,
}
impl GetAggregateResourceConfigInput {
    /// <p>The name of the configuration aggregator.</p>
    pub fn configuration_aggregator_name(&self) -> ::std::option::Option<&str> {
        self.configuration_aggregator_name.as_deref()
    }
    /// <p>An object that identifies aggregate resource.</p>
    pub fn resource_identifier(&self) -> ::std::option::Option<&crate::types::AggregateResourceIdentifier> {
        self.resource_identifier.as_ref()
    }
}
impl GetAggregateResourceConfigInput {
    /// Creates a new builder-style object to manufacture [`GetAggregateResourceConfigInput`](crate::operation::get_aggregate_resource_config::GetAggregateResourceConfigInput).
    pub fn builder() -> crate::operation::get_aggregate_resource_config::builders::GetAggregateResourceConfigInputBuilder {
        crate::operation::get_aggregate_resource_config::builders::GetAggregateResourceConfigInputBuilder::default()
    }
}

/// A builder for [`GetAggregateResourceConfigInput`](crate::operation::get_aggregate_resource_config::GetAggregateResourceConfigInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAggregateResourceConfigInputBuilder {
    pub(crate) configuration_aggregator_name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_identifier: ::std::option::Option<crate::types::AggregateResourceIdentifier>,
}
impl GetAggregateResourceConfigInputBuilder {
    /// <p>The name of the configuration aggregator.</p>
    /// This field is required.
    pub fn configuration_aggregator_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_aggregator_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration aggregator.</p>
    pub fn set_configuration_aggregator_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_aggregator_name = input;
        self
    }
    /// <p>The name of the configuration aggregator.</p>
    pub fn get_configuration_aggregator_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_aggregator_name
    }
    /// <p>An object that identifies aggregate resource.</p>
    /// This field is required.
    pub fn resource_identifier(mut self, input: crate::types::AggregateResourceIdentifier) -> Self {
        self.resource_identifier = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that identifies aggregate resource.</p>
    pub fn set_resource_identifier(mut self, input: ::std::option::Option<crate::types::AggregateResourceIdentifier>) -> Self {
        self.resource_identifier = input;
        self
    }
    /// <p>An object that identifies aggregate resource.</p>
    pub fn get_resource_identifier(&self) -> &::std::option::Option<crate::types::AggregateResourceIdentifier> {
        &self.resource_identifier
    }
    /// Consumes the builder and constructs a [`GetAggregateResourceConfigInput`](crate::operation::get_aggregate_resource_config::GetAggregateResourceConfigInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_aggregate_resource_config::GetAggregateResourceConfigInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_aggregate_resource_config::GetAggregateResourceConfigInput {
            configuration_aggregator_name: self.configuration_aggregator_name,
            resource_identifier: self.resource_identifier,
        })
    }
}

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFlowAliasOutput {
    /// <p>The name of the alias.</p>
    pub name: ::std::string::String,
    /// <p>The description of the flow.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about the version that the alias is mapped to.</p>
    pub routing_configuration: ::std::vec::Vec<crate::types::FlowAliasRoutingConfigurationListItem>,
    /// <p>The configuration that specifies how nodes in the flow are executed in parallel.</p>
    pub concurrency_configuration: ::std::option::Option<crate::types::FlowAliasConcurrencyConfiguration>,
    /// <p>The unique identifier of the flow that the alias belongs to.</p>
    pub flow_id: ::std::string::String,
    /// <p>The unique identifier of the alias of the flow.</p>
    pub id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the flow.</p>
    pub arn: ::std::string::String,
    /// <p>The time at which the flow was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The time at which the alias was last updated.</p>
    pub updated_at: ::aws_smithy_types::DateTime,
    _request_id: Option<String>,
}
impl GetFlowAliasOutput {
    /// <p>The name of the alias.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description of the flow.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Contains information about the version that the alias is mapped to.</p>
    pub fn routing_configuration(&self) -> &[crate::types::FlowAliasRoutingConfigurationListItem] {
        use std::ops::Deref;
        self.routing_configuration.deref()
    }
    /// <p>The configuration that specifies how nodes in the flow are executed in parallel.</p>
    pub fn concurrency_configuration(&self) -> ::std::option::Option<&crate::types::FlowAliasConcurrencyConfiguration> {
        self.concurrency_configuration.as_ref()
    }
    /// <p>The unique identifier of the flow that the alias belongs to.</p>
    pub fn flow_id(&self) -> &str {
        use std::ops::Deref;
        self.flow_id.deref()
    }
    /// <p>The unique identifier of the alias of the flow.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the flow.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The time at which the flow was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The time at which the alias was last updated.</p>
    pub fn updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.updated_at
    }
}
impl ::aws_types::request_id::RequestId for GetFlowAliasOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFlowAliasOutput {
    /// Creates a new builder-style object to manufacture [`GetFlowAliasOutput`](crate::operation::get_flow_alias::GetFlowAliasOutput).
    pub fn builder() -> crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder {
        crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder::default()
    }
}

/// A builder for [`GetFlowAliasOutput`](crate::operation::get_flow_alias::GetFlowAliasOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFlowAliasOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) routing_configuration: ::std::option::Option<::std::vec::Vec<crate::types::FlowAliasRoutingConfigurationListItem>>,
    pub(crate) concurrency_configuration: ::std::option::Option<crate::types::FlowAliasConcurrencyConfiguration>,
    pub(crate) flow_id: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetFlowAliasOutputBuilder {
    /// <p>The name of the alias.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the alias.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the alias.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the flow.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the flow.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the flow.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `routing_configuration`.
    ///
    /// To override the contents of this collection use [`set_routing_configuration`](Self::set_routing_configuration).
    ///
    /// <p>Contains information about the version that the alias is mapped to.</p>
    pub fn routing_configuration(mut self, input: crate::types::FlowAliasRoutingConfigurationListItem) -> Self {
        let mut v = self.routing_configuration.unwrap_or_default();
        v.push(input);
        self.routing_configuration = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains information about the version that the alias is mapped to.</p>
    pub fn set_routing_configuration(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::FlowAliasRoutingConfigurationListItem>>,
    ) -> Self {
        self.routing_configuration = input;
        self
    }
    /// <p>Contains information about the version that the alias is mapped to.</p>
    pub fn get_routing_configuration(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FlowAliasRoutingConfigurationListItem>> {
        &self.routing_configuration
    }
    /// <p>The configuration that specifies how nodes in the flow are executed in parallel.</p>
    pub fn concurrency_configuration(mut self, input: crate::types::FlowAliasConcurrencyConfiguration) -> Self {
        self.concurrency_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration that specifies how nodes in the flow are executed in parallel.</p>
    pub fn set_concurrency_configuration(mut self, input: ::std::option::Option<crate::types::FlowAliasConcurrencyConfiguration>) -> Self {
        self.concurrency_configuration = input;
        self
    }
    /// <p>The configuration that specifies how nodes in the flow are executed in parallel.</p>
    pub fn get_concurrency_configuration(&self) -> &::std::option::Option<crate::types::FlowAliasConcurrencyConfiguration> {
        &self.concurrency_configuration
    }
    /// <p>The unique identifier of the flow that the alias belongs to.</p>
    /// This field is required.
    pub fn flow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the flow that the alias belongs to.</p>
    pub fn set_flow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_id = input;
        self
    }
    /// <p>The unique identifier of the flow that the alias belongs to.</p>
    pub fn get_flow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_id
    }
    /// <p>The unique identifier of the alias of the flow.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the alias of the flow.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the alias of the flow.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the flow.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the flow.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the flow.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The time at which the flow was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the flow was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time at which the flow was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The time at which the alias was last updated.</p>
    /// This field is required.
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the alias was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The time at which the alias was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFlowAliasOutput`](crate::operation::get_flow_alias::GetFlowAliasOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder::name)
    /// - [`routing_configuration`](crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder::routing_configuration)
    /// - [`flow_id`](crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder::flow_id)
    /// - [`id`](crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder::id)
    /// - [`arn`](crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder::arn)
    /// - [`created_at`](crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder::created_at)
    /// - [`updated_at`](crate::operation::get_flow_alias::builders::GetFlowAliasOutputBuilder::updated_at)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_flow_alias::GetFlowAliasOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_flow_alias::GetFlowAliasOutput {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building GetFlowAliasOutput",
                )
            })?,
            description: self.description,
            routing_configuration: self.routing_configuration.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "routing_configuration",
                    "routing_configuration was not specified but it is required when building GetFlowAliasOutput",
                )
            })?,
            concurrency_configuration: self.concurrency_configuration,
            flow_id: self.flow_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "flow_id",
                    "flow_id was not specified but it is required when building GetFlowAliasOutput",
                )
            })?,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building GetFlowAliasOutput",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building GetFlowAliasOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building GetFlowAliasOutput",
                )
            })?,
            updated_at: self.updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_at",
                    "updated_at was not specified but it is required when building GetFlowAliasOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}

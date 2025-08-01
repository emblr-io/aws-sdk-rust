// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GetFlowVersionOutput {
    /// <p>The name of the version.</p>
    pub name: ::std::string::String,
    /// <p>The description of the flow.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the service role with permissions to create a flow. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-permissions.html">Create a service role for flows in Amazon Bedrock</a> in the Amazon Bedrock User Guide.</p>
    pub execution_role_arn: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the KMS key that the version of the flow is encrypted with.</p>
    pub customer_encryption_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the flow.</p>
    pub id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the flow.</p>
    pub arn: ::std::string::String,
    /// <p>The status of the flow.</p>
    pub status: crate::types::FlowStatus,
    /// <p>The time at which the flow was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The version of the flow for which information was retrieved.</p>
    pub version: ::std::string::String,
    /// <p>The definition of the nodes and connections between nodes in the flow.</p>
    pub definition: ::std::option::Option<crate::types::FlowDefinition>,
    _request_id: Option<String>,
}
impl GetFlowVersionOutput {
    /// <p>The name of the version.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description of the flow.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the service role with permissions to create a flow. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-permissions.html">Create a service role for flows in Amazon Bedrock</a> in the Amazon Bedrock User Guide.</p>
    pub fn execution_role_arn(&self) -> &str {
        use std::ops::Deref;
        self.execution_role_arn.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key that the version of the flow is encrypted with.</p>
    pub fn customer_encryption_key_arn(&self) -> ::std::option::Option<&str> {
        self.customer_encryption_key_arn.as_deref()
    }
    /// <p>The unique identifier of the flow.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the flow.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The status of the flow.</p>
    pub fn status(&self) -> &crate::types::FlowStatus {
        &self.status
    }
    /// <p>The time at which the flow was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The version of the flow for which information was retrieved.</p>
    pub fn version(&self) -> &str {
        use std::ops::Deref;
        self.version.deref()
    }
    /// <p>The definition of the nodes and connections between nodes in the flow.</p>
    pub fn definition(&self) -> ::std::option::Option<&crate::types::FlowDefinition> {
        self.definition.as_ref()
    }
}
impl ::std::fmt::Debug for GetFlowVersionOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetFlowVersionOutput");
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("execution_role_arn", &self.execution_role_arn);
        formatter.field("customer_encryption_key_arn", &self.customer_encryption_key_arn);
        formatter.field("id", &self.id);
        formatter.field("arn", &self.arn);
        formatter.field("status", &self.status);
        formatter.field("created_at", &self.created_at);
        formatter.field("version", &self.version);
        formatter.field("definition", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for GetFlowVersionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFlowVersionOutput {
    /// Creates a new builder-style object to manufacture [`GetFlowVersionOutput`](crate::operation::get_flow_version::GetFlowVersionOutput).
    pub fn builder() -> crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder {
        crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder::default()
    }
}

/// A builder for [`GetFlowVersionOutput`](crate::operation::get_flow_version::GetFlowVersionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GetFlowVersionOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) execution_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) customer_encryption_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::FlowStatus>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) definition: ::std::option::Option<crate::types::FlowDefinition>,
    _request_id: Option<String>,
}
impl GetFlowVersionOutputBuilder {
    /// <p>The name of the version.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the version.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the version.</p>
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
    /// <p>The Amazon Resource Name (ARN) of the service role with permissions to create a flow. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-permissions.html">Create a service role for flows in Amazon Bedrock</a> in the Amazon Bedrock User Guide.</p>
    /// This field is required.
    pub fn execution_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service role with permissions to create a flow. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-permissions.html">Create a service role for flows in Amazon Bedrock</a> in the Amazon Bedrock User Guide.</p>
    pub fn set_execution_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service role with permissions to create a flow. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-permissions.html">Create a service role for flows in Amazon Bedrock</a> in the Amazon Bedrock User Guide.</p>
    pub fn get_execution_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key that the version of the flow is encrypted with.</p>
    pub fn customer_encryption_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.customer_encryption_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key that the version of the flow is encrypted with.</p>
    pub fn set_customer_encryption_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.customer_encryption_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key that the version of the flow is encrypted with.</p>
    pub fn get_customer_encryption_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.customer_encryption_key_arn
    }
    /// <p>The unique identifier of the flow.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the flow.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the flow.</p>
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
    /// <p>The status of the flow.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::FlowStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the flow.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FlowStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the flow.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FlowStatus> {
        &self.status
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
    /// <p>The version of the flow for which information was retrieved.</p>
    /// This field is required.
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the flow for which information was retrieved.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the flow for which information was retrieved.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The definition of the nodes and connections between nodes in the flow.</p>
    pub fn definition(mut self, input: crate::types::FlowDefinition) -> Self {
        self.definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The definition of the nodes and connections between nodes in the flow.</p>
    pub fn set_definition(mut self, input: ::std::option::Option<crate::types::FlowDefinition>) -> Self {
        self.definition = input;
        self
    }
    /// <p>The definition of the nodes and connections between nodes in the flow.</p>
    pub fn get_definition(&self) -> &::std::option::Option<crate::types::FlowDefinition> {
        &self.definition
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFlowVersionOutput`](crate::operation::get_flow_version::GetFlowVersionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder::name)
    /// - [`execution_role_arn`](crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder::execution_role_arn)
    /// - [`id`](crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder::id)
    /// - [`arn`](crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder::arn)
    /// - [`status`](crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder::status)
    /// - [`created_at`](crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder::created_at)
    /// - [`version`](crate::operation::get_flow_version::builders::GetFlowVersionOutputBuilder::version)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_flow_version::GetFlowVersionOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_flow_version::GetFlowVersionOutput {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building GetFlowVersionOutput",
                )
            })?,
            description: self.description,
            execution_role_arn: self.execution_role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "execution_role_arn",
                    "execution_role_arn was not specified but it is required when building GetFlowVersionOutput",
                )
            })?,
            customer_encryption_key_arn: self.customer_encryption_key_arn,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building GetFlowVersionOutput",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building GetFlowVersionOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetFlowVersionOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building GetFlowVersionOutput",
                )
            })?,
            version: self.version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "version",
                    "version was not specified but it is required when building GetFlowVersionOutput",
                )
            })?,
            definition: self.definition,
            _request_id: self._request_id,
        })
    }
}
impl ::std::fmt::Debug for GetFlowVersionOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetFlowVersionOutputBuilder");
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("execution_role_arn", &self.execution_role_arn);
        formatter.field("customer_encryption_key_arn", &self.customer_encryption_key_arn);
        formatter.field("id", &self.id);
        formatter.field("arn", &self.arn);
        formatter.field("status", &self.status);
        formatter.field("created_at", &self.created_at);
        formatter.field("version", &self.version);
        formatter.field("definition", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}

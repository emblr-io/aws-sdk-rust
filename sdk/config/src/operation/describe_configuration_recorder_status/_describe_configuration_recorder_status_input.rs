// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input for the <code>DescribeConfigurationRecorderStatus</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConfigurationRecorderStatusInput {
    /// <p>The name of the configuration recorder. If the name is not specified, the opertation returns the status for the customer managed configuration recorder configured for the account, if applicable.</p><note>
    /// <p>When making a request to this operation, you can only specify one configuration recorder.</p>
    /// </note>
    pub configuration_recorder_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>For service-linked configuration recorders, you can use the service principal of the linked Amazon Web Services service to specify the configuration recorder.</p>
    pub service_principal: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the configuration recorder that you want to specify.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl DescribeConfigurationRecorderStatusInput {
    /// <p>The name of the configuration recorder. If the name is not specified, the opertation returns the status for the customer managed configuration recorder configured for the account, if applicable.</p><note>
    /// <p>When making a request to this operation, you can only specify one configuration recorder.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.configuration_recorder_names.is_none()`.
    pub fn configuration_recorder_names(&self) -> &[::std::string::String] {
        self.configuration_recorder_names.as_deref().unwrap_or_default()
    }
    /// <p>For service-linked configuration recorders, you can use the service principal of the linked Amazon Web Services service to specify the configuration recorder.</p>
    pub fn service_principal(&self) -> ::std::option::Option<&str> {
        self.service_principal.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the configuration recorder that you want to specify.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl DescribeConfigurationRecorderStatusInput {
    /// Creates a new builder-style object to manufacture [`DescribeConfigurationRecorderStatusInput`](crate::operation::describe_configuration_recorder_status::DescribeConfigurationRecorderStatusInput).
    pub fn builder() -> crate::operation::describe_configuration_recorder_status::builders::DescribeConfigurationRecorderStatusInputBuilder {
        crate::operation::describe_configuration_recorder_status::builders::DescribeConfigurationRecorderStatusInputBuilder::default()
    }
}

/// A builder for [`DescribeConfigurationRecorderStatusInput`](crate::operation::describe_configuration_recorder_status::DescribeConfigurationRecorderStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConfigurationRecorderStatusInputBuilder {
    pub(crate) configuration_recorder_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) service_principal: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl DescribeConfigurationRecorderStatusInputBuilder {
    /// Appends an item to `configuration_recorder_names`.
    ///
    /// To override the contents of this collection use [`set_configuration_recorder_names`](Self::set_configuration_recorder_names).
    ///
    /// <p>The name of the configuration recorder. If the name is not specified, the opertation returns the status for the customer managed configuration recorder configured for the account, if applicable.</p><note>
    /// <p>When making a request to this operation, you can only specify one configuration recorder.</p>
    /// </note>
    pub fn configuration_recorder_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.configuration_recorder_names.unwrap_or_default();
        v.push(input.into());
        self.configuration_recorder_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The name of the configuration recorder. If the name is not specified, the opertation returns the status for the customer managed configuration recorder configured for the account, if applicable.</p><note>
    /// <p>When making a request to this operation, you can only specify one configuration recorder.</p>
    /// </note>
    pub fn set_configuration_recorder_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.configuration_recorder_names = input;
        self
    }
    /// <p>The name of the configuration recorder. If the name is not specified, the opertation returns the status for the customer managed configuration recorder configured for the account, if applicable.</p><note>
    /// <p>When making a request to this operation, you can only specify one configuration recorder.</p>
    /// </note>
    pub fn get_configuration_recorder_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.configuration_recorder_names
    }
    /// <p>For service-linked configuration recorders, you can use the service principal of the linked Amazon Web Services service to specify the configuration recorder.</p>
    pub fn service_principal(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_principal = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For service-linked configuration recorders, you can use the service principal of the linked Amazon Web Services service to specify the configuration recorder.</p>
    pub fn set_service_principal(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_principal = input;
        self
    }
    /// <p>For service-linked configuration recorders, you can use the service principal of the linked Amazon Web Services service to specify the configuration recorder.</p>
    pub fn get_service_principal(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_principal
    }
    /// <p>The Amazon Resource Name (ARN) of the configuration recorder that you want to specify.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configuration recorder that you want to specify.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the configuration recorder that you want to specify.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`DescribeConfigurationRecorderStatusInput`](crate::operation::describe_configuration_recorder_status::DescribeConfigurationRecorderStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_configuration_recorder_status::DescribeConfigurationRecorderStatusInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_configuration_recorder_status::DescribeConfigurationRecorderStatusInput {
                configuration_recorder_names: self.configuration_recorder_names,
                service_principal: self.service_principal,
                arn: self.arn,
            },
        )
    }
}

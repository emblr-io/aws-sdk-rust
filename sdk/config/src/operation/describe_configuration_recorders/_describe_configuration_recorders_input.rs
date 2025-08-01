// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input for the <code>DescribeConfigurationRecorders</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConfigurationRecordersInput {
    /// <p>A list of names of the configuration recorders that you want to specify.</p>
    pub configuration_recorder_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>For service-linked configuration recorders, you can use the service principal of the linked Amazon Web Services service to specify the configuration recorder.</p>
    pub service_principal: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the configuration recorder that you want to specify.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl DescribeConfigurationRecordersInput {
    /// <p>A list of names of the configuration recorders that you want to specify.</p>
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
impl DescribeConfigurationRecordersInput {
    /// Creates a new builder-style object to manufacture [`DescribeConfigurationRecordersInput`](crate::operation::describe_configuration_recorders::DescribeConfigurationRecordersInput).
    pub fn builder() -> crate::operation::describe_configuration_recorders::builders::DescribeConfigurationRecordersInputBuilder {
        crate::operation::describe_configuration_recorders::builders::DescribeConfigurationRecordersInputBuilder::default()
    }
}

/// A builder for [`DescribeConfigurationRecordersInput`](crate::operation::describe_configuration_recorders::DescribeConfigurationRecordersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConfigurationRecordersInputBuilder {
    pub(crate) configuration_recorder_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) service_principal: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl DescribeConfigurationRecordersInputBuilder {
    /// Appends an item to `configuration_recorder_names`.
    ///
    /// To override the contents of this collection use [`set_configuration_recorder_names`](Self::set_configuration_recorder_names).
    ///
    /// <p>A list of names of the configuration recorders that you want to specify.</p>
    pub fn configuration_recorder_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.configuration_recorder_names.unwrap_or_default();
        v.push(input.into());
        self.configuration_recorder_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of names of the configuration recorders that you want to specify.</p>
    pub fn set_configuration_recorder_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.configuration_recorder_names = input;
        self
    }
    /// <p>A list of names of the configuration recorders that you want to specify.</p>
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
    /// Consumes the builder and constructs a [`DescribeConfigurationRecordersInput`](crate::operation::describe_configuration_recorders::DescribeConfigurationRecordersInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_configuration_recorders::DescribeConfigurationRecordersInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_configuration_recorders::DescribeConfigurationRecordersInput {
            configuration_recorder_names: self.configuration_recorder_names,
            service_principal: self.service_principal,
            arn: self.arn,
        })
    }
}

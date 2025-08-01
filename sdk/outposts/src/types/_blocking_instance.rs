// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A running Amazon EC2 instance that can be stopped to free up capacity needed to run the capacity task.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BlockingInstance {
    /// <p>The ID of the blocking instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon Web Services account.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services service name that owns the specified blocking instance.</p>
    pub aws_service_name: ::std::option::Option<crate::types::AwsServiceName>,
}
impl BlockingInstance {
    /// <p>The ID of the blocking instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The Amazon Web Services service name that owns the specified blocking instance.</p>
    pub fn aws_service_name(&self) -> ::std::option::Option<&crate::types::AwsServiceName> {
        self.aws_service_name.as_ref()
    }
}
impl BlockingInstance {
    /// Creates a new builder-style object to manufacture [`BlockingInstance`](crate::types::BlockingInstance).
    pub fn builder() -> crate::types::builders::BlockingInstanceBuilder {
        crate::types::builders::BlockingInstanceBuilder::default()
    }
}

/// A builder for [`BlockingInstance`](crate::types::BlockingInstance).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BlockingInstanceBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_service_name: ::std::option::Option<crate::types::AwsServiceName>,
}
impl BlockingInstanceBuilder {
    /// <p>The ID of the blocking instance.</p>
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the blocking instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the blocking instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The Amazon Web Services service name that owns the specified blocking instance.</p>
    pub fn aws_service_name(mut self, input: crate::types::AwsServiceName) -> Self {
        self.aws_service_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Web Services service name that owns the specified blocking instance.</p>
    pub fn set_aws_service_name(mut self, input: ::std::option::Option<crate::types::AwsServiceName>) -> Self {
        self.aws_service_name = input;
        self
    }
    /// <p>The Amazon Web Services service name that owns the specified blocking instance.</p>
    pub fn get_aws_service_name(&self) -> &::std::option::Option<crate::types::AwsServiceName> {
        &self.aws_service_name
    }
    /// Consumes the builder and constructs a [`BlockingInstance`](crate::types::BlockingInstance).
    pub fn build(self) -> crate::types::BlockingInstance {
        crate::types::BlockingInstance {
            instance_id: self.instance_id,
            account_id: self.account_id,
            aws_service_name: self.aws_service_name,
        }
    }
}

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAppInstanceUserEndpointInput {
    /// <p>The ARN of the <code>AppInstanceUser</code>.</p>
    pub app_instance_user_arn: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the <code>AppInstanceUserEndpoint</code>.</p>
    pub endpoint_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAppInstanceUserEndpointInput {
    /// <p>The ARN of the <code>AppInstanceUser</code>.</p>
    pub fn app_instance_user_arn(&self) -> ::std::option::Option<&str> {
        self.app_instance_user_arn.as_deref()
    }
    /// <p>The unique identifier of the <code>AppInstanceUserEndpoint</code>.</p>
    pub fn endpoint_id(&self) -> ::std::option::Option<&str> {
        self.endpoint_id.as_deref()
    }
}
impl DescribeAppInstanceUserEndpointInput {
    /// Creates a new builder-style object to manufacture [`DescribeAppInstanceUserEndpointInput`](crate::operation::describe_app_instance_user_endpoint::DescribeAppInstanceUserEndpointInput).
    pub fn builder() -> crate::operation::describe_app_instance_user_endpoint::builders::DescribeAppInstanceUserEndpointInputBuilder {
        crate::operation::describe_app_instance_user_endpoint::builders::DescribeAppInstanceUserEndpointInputBuilder::default()
    }
}

/// A builder for [`DescribeAppInstanceUserEndpointInput`](crate::operation::describe_app_instance_user_endpoint::DescribeAppInstanceUserEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAppInstanceUserEndpointInputBuilder {
    pub(crate) app_instance_user_arn: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAppInstanceUserEndpointInputBuilder {
    /// <p>The ARN of the <code>AppInstanceUser</code>.</p>
    /// This field is required.
    pub fn app_instance_user_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_instance_user_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the <code>AppInstanceUser</code>.</p>
    pub fn set_app_instance_user_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_instance_user_arn = input;
        self
    }
    /// <p>The ARN of the <code>AppInstanceUser</code>.</p>
    pub fn get_app_instance_user_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_instance_user_arn
    }
    /// <p>The unique identifier of the <code>AppInstanceUserEndpoint</code>.</p>
    /// This field is required.
    pub fn endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the <code>AppInstanceUserEndpoint</code>.</p>
    pub fn set_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_id = input;
        self
    }
    /// <p>The unique identifier of the <code>AppInstanceUserEndpoint</code>.</p>
    pub fn get_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_id
    }
    /// Consumes the builder and constructs a [`DescribeAppInstanceUserEndpointInput`](crate::operation::describe_app_instance_user_endpoint::DescribeAppInstanceUserEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_app_instance_user_endpoint::DescribeAppInstanceUserEndpointInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_app_instance_user_endpoint::DescribeAppInstanceUserEndpointInput {
                app_instance_user_arn: self.app_instance_user_arn,
                endpoint_id: self.endpoint_id,
            },
        )
    }
}

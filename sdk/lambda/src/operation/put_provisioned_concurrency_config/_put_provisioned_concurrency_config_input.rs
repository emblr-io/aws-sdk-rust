// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutProvisionedConcurrencyConfigInput {
    /// <p>The name or ARN of the Lambda function.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code>.</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    pub function_name: ::std::option::Option<::std::string::String>,
    /// <p>The version number or alias name.</p>
    pub qualifier: ::std::option::Option<::std::string::String>,
    /// <p>The amount of provisioned concurrency to allocate for the version or alias.</p>
    pub provisioned_concurrent_executions: ::std::option::Option<i32>,
}
impl PutProvisionedConcurrencyConfigInput {
    /// <p>The name or ARN of the Lambda function.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code>.</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    pub fn function_name(&self) -> ::std::option::Option<&str> {
        self.function_name.as_deref()
    }
    /// <p>The version number or alias name.</p>
    pub fn qualifier(&self) -> ::std::option::Option<&str> {
        self.qualifier.as_deref()
    }
    /// <p>The amount of provisioned concurrency to allocate for the version or alias.</p>
    pub fn provisioned_concurrent_executions(&self) -> ::std::option::Option<i32> {
        self.provisioned_concurrent_executions
    }
}
impl PutProvisionedConcurrencyConfigInput {
    /// Creates a new builder-style object to manufacture [`PutProvisionedConcurrencyConfigInput`](crate::operation::put_provisioned_concurrency_config::PutProvisionedConcurrencyConfigInput).
    pub fn builder() -> crate::operation::put_provisioned_concurrency_config::builders::PutProvisionedConcurrencyConfigInputBuilder {
        crate::operation::put_provisioned_concurrency_config::builders::PutProvisionedConcurrencyConfigInputBuilder::default()
    }
}

/// A builder for [`PutProvisionedConcurrencyConfigInput`](crate::operation::put_provisioned_concurrency_config::PutProvisionedConcurrencyConfigInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutProvisionedConcurrencyConfigInputBuilder {
    pub(crate) function_name: ::std::option::Option<::std::string::String>,
    pub(crate) qualifier: ::std::option::Option<::std::string::String>,
    pub(crate) provisioned_concurrent_executions: ::std::option::Option<i32>,
}
impl PutProvisionedConcurrencyConfigInputBuilder {
    /// <p>The name or ARN of the Lambda function.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code>.</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    /// This field is required.
    pub fn function_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the Lambda function.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code>.</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    pub fn set_function_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function_name = input;
        self
    }
    /// <p>The name or ARN of the Lambda function.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code>.</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    pub fn get_function_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.function_name
    }
    /// <p>The version number or alias name.</p>
    /// This field is required.
    pub fn qualifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.qualifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version number or alias name.</p>
    pub fn set_qualifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.qualifier = input;
        self
    }
    /// <p>The version number or alias name.</p>
    pub fn get_qualifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.qualifier
    }
    /// <p>The amount of provisioned concurrency to allocate for the version or alias.</p>
    /// This field is required.
    pub fn provisioned_concurrent_executions(mut self, input: i32) -> Self {
        self.provisioned_concurrent_executions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of provisioned concurrency to allocate for the version or alias.</p>
    pub fn set_provisioned_concurrent_executions(mut self, input: ::std::option::Option<i32>) -> Self {
        self.provisioned_concurrent_executions = input;
        self
    }
    /// <p>The amount of provisioned concurrency to allocate for the version or alias.</p>
    pub fn get_provisioned_concurrent_executions(&self) -> &::std::option::Option<i32> {
        &self.provisioned_concurrent_executions
    }
    /// Consumes the builder and constructs a [`PutProvisionedConcurrencyConfigInput`](crate::operation::put_provisioned_concurrency_config::PutProvisionedConcurrencyConfigInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_provisioned_concurrency_config::PutProvisionedConcurrencyConfigInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_provisioned_concurrency_config::PutProvisionedConcurrencyConfigInput {
                function_name: self.function_name,
                qualifier: self.qualifier,
                provisioned_concurrent_executions: self.provisioned_concurrent_executions,
            },
        )
    }
}

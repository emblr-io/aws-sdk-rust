// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListProvisionedConcurrencyConfigsInput {
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
    /// <p>Specify the pagination token that's returned by a previous request to retrieve the next page of results.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>Specify a number to limit the number of configurations returned.</p>
    pub max_items: ::std::option::Option<i32>,
}
impl ListProvisionedConcurrencyConfigsInput {
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
    /// <p>Specify the pagination token that's returned by a previous request to retrieve the next page of results.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>Specify a number to limit the number of configurations returned.</p>
    pub fn max_items(&self) -> ::std::option::Option<i32> {
        self.max_items
    }
}
impl ListProvisionedConcurrencyConfigsInput {
    /// Creates a new builder-style object to manufacture [`ListProvisionedConcurrencyConfigsInput`](crate::operation::list_provisioned_concurrency_configs::ListProvisionedConcurrencyConfigsInput).
    pub fn builder() -> crate::operation::list_provisioned_concurrency_configs::builders::ListProvisionedConcurrencyConfigsInputBuilder {
        crate::operation::list_provisioned_concurrency_configs::builders::ListProvisionedConcurrencyConfigsInputBuilder::default()
    }
}

/// A builder for [`ListProvisionedConcurrencyConfigsInput`](crate::operation::list_provisioned_concurrency_configs::ListProvisionedConcurrencyConfigsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListProvisionedConcurrencyConfigsInputBuilder {
    pub(crate) function_name: ::std::option::Option<::std::string::String>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
}
impl ListProvisionedConcurrencyConfigsInputBuilder {
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
    /// <p>Specify the pagination token that's returned by a previous request to retrieve the next page of results.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify the pagination token that's returned by a previous request to retrieve the next page of results.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Specify the pagination token that's returned by a previous request to retrieve the next page of results.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>Specify a number to limit the number of configurations returned.</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify a number to limit the number of configurations returned.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>Specify a number to limit the number of configurations returned.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// Consumes the builder and constructs a [`ListProvisionedConcurrencyConfigsInput`](crate::operation::list_provisioned_concurrency_configs::ListProvisionedConcurrencyConfigsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_provisioned_concurrency_configs::ListProvisionedConcurrencyConfigsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_provisioned_concurrency_configs::ListProvisionedConcurrencyConfigsInput {
                function_name: self.function_name,
                marker: self.marker,
                max_items: self.max_items,
            },
        )
    }
}

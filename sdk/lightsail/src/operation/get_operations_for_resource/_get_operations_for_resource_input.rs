// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOperationsForResourceInput {
    /// <p>The name of the resource for which you are requesting information.</p>
    pub resource_name: ::std::option::Option<::std::string::String>,
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetOperationsForResource</code> request. If your results are paginated, the response will return a next page token that you can specify as the page token in a subsequent request.</p>
    pub page_token: ::std::option::Option<::std::string::String>,
}
impl GetOperationsForResourceInput {
    /// <p>The name of the resource for which you are requesting information.</p>
    pub fn resource_name(&self) -> ::std::option::Option<&str> {
        self.resource_name.as_deref()
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetOperationsForResource</code> request. If your results are paginated, the response will return a next page token that you can specify as the page token in a subsequent request.</p>
    pub fn page_token(&self) -> ::std::option::Option<&str> {
        self.page_token.as_deref()
    }
}
impl GetOperationsForResourceInput {
    /// Creates a new builder-style object to manufacture [`GetOperationsForResourceInput`](crate::operation::get_operations_for_resource::GetOperationsForResourceInput).
    pub fn builder() -> crate::operation::get_operations_for_resource::builders::GetOperationsForResourceInputBuilder {
        crate::operation::get_operations_for_resource::builders::GetOperationsForResourceInputBuilder::default()
    }
}

/// A builder for [`GetOperationsForResourceInput`](crate::operation::get_operations_for_resource::GetOperationsForResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOperationsForResourceInputBuilder {
    pub(crate) resource_name: ::std::option::Option<::std::string::String>,
    pub(crate) page_token: ::std::option::Option<::std::string::String>,
}
impl GetOperationsForResourceInputBuilder {
    /// <p>The name of the resource for which you are requesting information.</p>
    /// This field is required.
    pub fn resource_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource for which you are requesting information.</p>
    pub fn set_resource_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_name = input;
        self
    }
    /// <p>The name of the resource for which you are requesting information.</p>
    pub fn get_resource_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_name
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetOperationsForResource</code> request. If your results are paginated, the response will return a next page token that you can specify as the page token in a subsequent request.</p>
    pub fn page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetOperationsForResource</code> request. If your results are paginated, the response will return a next page token that you can specify as the page token in a subsequent request.</p>
    pub fn set_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.page_token = input;
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>To get a page token, perform an initial <code>GetOperationsForResource</code> request. If your results are paginated, the response will return a next page token that you can specify as the page token in a subsequent request.</p>
    pub fn get_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.page_token
    }
    /// Consumes the builder and constructs a [`GetOperationsForResourceInput`](crate::operation::get_operations_for_resource::GetOperationsForResourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_operations_for_resource::GetOperationsForResourceInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_operations_for_resource::GetOperationsForResourceInput {
            resource_name: self.resource_name,
            page_token: self.page_token,
        })
    }
}

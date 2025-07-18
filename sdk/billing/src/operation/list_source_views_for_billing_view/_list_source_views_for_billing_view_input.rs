// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSourceViewsForBillingViewInput {
    /// <p>The Amazon Resource Name (ARN) that can be used to uniquely identify the billing view.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The number of entries a paginated response contains.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListSourceViewsForBillingViewInput {
    /// <p>The Amazon Resource Name (ARN) that can be used to uniquely identify the billing view.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The number of entries a paginated response contains.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListSourceViewsForBillingViewInput {
    /// Creates a new builder-style object to manufacture [`ListSourceViewsForBillingViewInput`](crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewInput).
    pub fn builder() -> crate::operation::list_source_views_for_billing_view::builders::ListSourceViewsForBillingViewInputBuilder {
        crate::operation::list_source_views_for_billing_view::builders::ListSourceViewsForBillingViewInputBuilder::default()
    }
}

/// A builder for [`ListSourceViewsForBillingViewInput`](crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSourceViewsForBillingViewInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListSourceViewsForBillingViewInputBuilder {
    /// <p>The Amazon Resource Name (ARN) that can be used to uniquely identify the billing view.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that can be used to uniquely identify the billing view.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that can be used to uniquely identify the billing view.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The number of entries a paginated response contains.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of entries a paginated response contains.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The number of entries a paginated response contains.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token that is used on subsequent calls to list billing views.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListSourceViewsForBillingViewInput`](crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_source_views_for_billing_view::ListSourceViewsForBillingViewInput {
            arn: self.arn,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}

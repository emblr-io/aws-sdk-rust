// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListContextsInput {
    /// <p>A filter that returns only contexts with the specified source URI.</p>
    pub source_uri: ::std::option::Option<::std::string::String>,
    /// <p>A filter that returns only contexts of the specified type.</p>
    pub context_type: ::std::option::Option<::std::string::String>,
    /// <p>A filter that returns only contexts created on or after the specified time.</p>
    pub created_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A filter that returns only contexts created on or before the specified time.</p>
    pub created_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The property used to sort results. The default value is <code>CreationTime</code>.</p>
    pub sort_by: ::std::option::Option<crate::types::SortContextsBy>,
    /// <p>The sort order. The default value is <code>Descending</code>.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
    /// <p>If the previous call to <code>ListContexts</code> didn't return the full set of contexts, the call returns a token for getting the next set of contexts.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of contexts to return in the response. The default value is 10.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListContextsInput {
    /// <p>A filter that returns only contexts with the specified source URI.</p>
    pub fn source_uri(&self) -> ::std::option::Option<&str> {
        self.source_uri.as_deref()
    }
    /// <p>A filter that returns only contexts of the specified type.</p>
    pub fn context_type(&self) -> ::std::option::Option<&str> {
        self.context_type.as_deref()
    }
    /// <p>A filter that returns only contexts created on or after the specified time.</p>
    pub fn created_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_after.as_ref()
    }
    /// <p>A filter that returns only contexts created on or before the specified time.</p>
    pub fn created_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_before.as_ref()
    }
    /// <p>The property used to sort results. The default value is <code>CreationTime</code>.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::SortContextsBy> {
        self.sort_by.as_ref()
    }
    /// <p>The sort order. The default value is <code>Descending</code>.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>If the previous call to <code>ListContexts</code> didn't return the full set of contexts, the call returns a token for getting the next set of contexts.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of contexts to return in the response. The default value is 10.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListContextsInput {
    /// Creates a new builder-style object to manufacture [`ListContextsInput`](crate::operation::list_contexts::ListContextsInput).
    pub fn builder() -> crate::operation::list_contexts::builders::ListContextsInputBuilder {
        crate::operation::list_contexts::builders::ListContextsInputBuilder::default()
    }
}

/// A builder for [`ListContextsInput`](crate::operation::list_contexts::ListContextsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListContextsInputBuilder {
    pub(crate) source_uri: ::std::option::Option<::std::string::String>,
    pub(crate) context_type: ::std::option::Option<::std::string::String>,
    pub(crate) created_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) sort_by: ::std::option::Option<crate::types::SortContextsBy>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListContextsInputBuilder {
    /// <p>A filter that returns only contexts with the specified source URI.</p>
    pub fn source_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A filter that returns only contexts with the specified source URI.</p>
    pub fn set_source_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_uri = input;
        self
    }
    /// <p>A filter that returns only contexts with the specified source URI.</p>
    pub fn get_source_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_uri
    }
    /// <p>A filter that returns only contexts of the specified type.</p>
    pub fn context_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.context_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A filter that returns only contexts of the specified type.</p>
    pub fn set_context_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.context_type = input;
        self
    }
    /// <p>A filter that returns only contexts of the specified type.</p>
    pub fn get_context_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.context_type
    }
    /// <p>A filter that returns only contexts created on or after the specified time.</p>
    pub fn created_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only contexts created on or after the specified time.</p>
    pub fn set_created_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_after = input;
        self
    }
    /// <p>A filter that returns only contexts created on or after the specified time.</p>
    pub fn get_created_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_after
    }
    /// <p>A filter that returns only contexts created on or before the specified time.</p>
    pub fn created_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only contexts created on or before the specified time.</p>
    pub fn set_created_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_before = input;
        self
    }
    /// <p>A filter that returns only contexts created on or before the specified time.</p>
    pub fn get_created_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_before
    }
    /// <p>The property used to sort results. The default value is <code>CreationTime</code>.</p>
    pub fn sort_by(mut self, input: crate::types::SortContextsBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The property used to sort results. The default value is <code>CreationTime</code>.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::SortContextsBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The property used to sort results. The default value is <code>CreationTime</code>.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::SortContextsBy> {
        &self.sort_by
    }
    /// <p>The sort order. The default value is <code>Descending</code>.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort order. The default value is <code>Descending</code>.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The sort order. The default value is <code>Descending</code>.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// <p>If the previous call to <code>ListContexts</code> didn't return the full set of contexts, the call returns a token for getting the next set of contexts.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the previous call to <code>ListContexts</code> didn't return the full set of contexts, the call returns a token for getting the next set of contexts.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the previous call to <code>ListContexts</code> didn't return the full set of contexts, the call returns a token for getting the next set of contexts.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of contexts to return in the response. The default value is 10.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of contexts to return in the response. The default value is 10.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of contexts to return in the response. The default value is 10.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListContextsInput`](crate::operation::list_contexts::ListContextsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_contexts::ListContextsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_contexts::ListContextsInput {
            source_uri: self.source_uri,
            context_type: self.context_type,
            created_after: self.created_after,
            created_before: self.created_before,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}

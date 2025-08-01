// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListControlMappingsInput {
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results on a page or for an API request call.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>An optional filter that narrows the results to specific control mappings based on control ARNs, common control ARNs, or mapping types.</p>
    pub filter: ::std::option::Option<crate::types::ControlMappingFilter>,
}
impl ListControlMappingsInput {
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results on a page or for an API request call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>An optional filter that narrows the results to specific control mappings based on control ARNs, common control ARNs, or mapping types.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::ControlMappingFilter> {
        self.filter.as_ref()
    }
}
impl ListControlMappingsInput {
    /// Creates a new builder-style object to manufacture [`ListControlMappingsInput`](crate::operation::list_control_mappings::ListControlMappingsInput).
    pub fn builder() -> crate::operation::list_control_mappings::builders::ListControlMappingsInputBuilder {
        crate::operation::list_control_mappings::builders::ListControlMappingsInputBuilder::default()
    }
}

/// A builder for [`ListControlMappingsInput`](crate::operation::list_control_mappings::ListControlMappingsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListControlMappingsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) filter: ::std::option::Option<crate::types::ControlMappingFilter>,
}
impl ListControlMappingsInputBuilder {
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results on a page or for an API request call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results on a page or for an API request call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results on a page or for an API request call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>An optional filter that narrows the results to specific control mappings based on control ARNs, common control ARNs, or mapping types.</p>
    pub fn filter(mut self, input: crate::types::ControlMappingFilter) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>An optional filter that narrows the results to specific control mappings based on control ARNs, common control ARNs, or mapping types.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::ControlMappingFilter>) -> Self {
        self.filter = input;
        self
    }
    /// <p>An optional filter that narrows the results to specific control mappings based on control ARNs, common control ARNs, or mapping types.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::ControlMappingFilter> {
        &self.filter
    }
    /// Consumes the builder and constructs a [`ListControlMappingsInput`](crate::operation::list_control_mappings::ListControlMappingsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_control_mappings::ListControlMappingsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_control_mappings::ListControlMappingsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            filter: self.filter,
        })
    }
}

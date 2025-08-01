// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListReleaseLabelsInput {
    /// <p>Filters the results of the request. <code>Prefix</code> specifies the prefix of release labels to return. <code>Application</code> specifies the application (with/without version) of release labels to return.</p>
    pub filters: ::std::option::Option<crate::types::ReleaseLabelFilter>,
    /// <p>Specifies the next page of results. If <code>NextToken</code> is not specified, which is usually the case for the first request of ListReleaseLabels, the first page of results are determined by other filtering parameters or by the latest version. The <code>ListReleaseLabels</code> request fails if the identity (Amazon Web Services account ID) and all filtering parameters are different from the original request, or if the <code>NextToken</code> is expired or tampered with.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Defines the maximum number of release labels to return in a single response. The default is <code>100</code>.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListReleaseLabelsInput {
    /// <p>Filters the results of the request. <code>Prefix</code> specifies the prefix of release labels to return. <code>Application</code> specifies the application (with/without version) of release labels to return.</p>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::ReleaseLabelFilter> {
        self.filters.as_ref()
    }
    /// <p>Specifies the next page of results. If <code>NextToken</code> is not specified, which is usually the case for the first request of ListReleaseLabels, the first page of results are determined by other filtering parameters or by the latest version. The <code>ListReleaseLabels</code> request fails if the identity (Amazon Web Services account ID) and all filtering parameters are different from the original request, or if the <code>NextToken</code> is expired or tampered with.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Defines the maximum number of release labels to return in a single response. The default is <code>100</code>.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListReleaseLabelsInput {
    /// Creates a new builder-style object to manufacture [`ListReleaseLabelsInput`](crate::operation::list_release_labels::ListReleaseLabelsInput).
    pub fn builder() -> crate::operation::list_release_labels::builders::ListReleaseLabelsInputBuilder {
        crate::operation::list_release_labels::builders::ListReleaseLabelsInputBuilder::default()
    }
}

/// A builder for [`ListReleaseLabelsInput`](crate::operation::list_release_labels::ListReleaseLabelsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListReleaseLabelsInputBuilder {
    pub(crate) filters: ::std::option::Option<crate::types::ReleaseLabelFilter>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListReleaseLabelsInputBuilder {
    /// <p>Filters the results of the request. <code>Prefix</code> specifies the prefix of release labels to return. <code>Application</code> specifies the application (with/without version) of release labels to return.</p>
    pub fn filters(mut self, input: crate::types::ReleaseLabelFilter) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters the results of the request. <code>Prefix</code> specifies the prefix of release labels to return. <code>Application</code> specifies the application (with/without version) of release labels to return.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::ReleaseLabelFilter>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Filters the results of the request. <code>Prefix</code> specifies the prefix of release labels to return. <code>Application</code> specifies the application (with/without version) of release labels to return.</p>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::ReleaseLabelFilter> {
        &self.filters
    }
    /// <p>Specifies the next page of results. If <code>NextToken</code> is not specified, which is usually the case for the first request of ListReleaseLabels, the first page of results are determined by other filtering parameters or by the latest version. The <code>ListReleaseLabels</code> request fails if the identity (Amazon Web Services account ID) and all filtering parameters are different from the original request, or if the <code>NextToken</code> is expired or tampered with.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the next page of results. If <code>NextToken</code> is not specified, which is usually the case for the first request of ListReleaseLabels, the first page of results are determined by other filtering parameters or by the latest version. The <code>ListReleaseLabels</code> request fails if the identity (Amazon Web Services account ID) and all filtering parameters are different from the original request, or if the <code>NextToken</code> is expired or tampered with.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Specifies the next page of results. If <code>NextToken</code> is not specified, which is usually the case for the first request of ListReleaseLabels, the first page of results are determined by other filtering parameters or by the latest version. The <code>ListReleaseLabels</code> request fails if the identity (Amazon Web Services account ID) and all filtering parameters are different from the original request, or if the <code>NextToken</code> is expired or tampered with.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Defines the maximum number of release labels to return in a single response. The default is <code>100</code>.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the maximum number of release labels to return in a single response. The default is <code>100</code>.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Defines the maximum number of release labels to return in a single response. The default is <code>100</code>.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListReleaseLabelsInput`](crate::operation::list_release_labels::ListReleaseLabelsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_release_labels::ListReleaseLabelsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_release_labels::ListReleaseLabelsInput {
            filters: self.filters,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}

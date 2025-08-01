// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchDashboardsInput {
    /// <p>The ID of the Amazon Web Services account that contains the user whose dashboards you're searching for.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The filters to apply to the search. Currently, you can search only by user name, for example, <code>"Filters": \[ { "Name": "QUICKSIGHT_USER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1" } \]</code></p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::DashboardSearchFilter>>,
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to be returned per request.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl SearchDashboardsInput {
    /// <p>The ID of the Amazon Web Services account that contains the user whose dashboards you're searching for.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The filters to apply to the search. Currently, you can search only by user name, for example, <code>"Filters": \[ { "Name": "QUICKSIGHT_USER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1" } \]</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::DashboardSearchFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl SearchDashboardsInput {
    /// Creates a new builder-style object to manufacture [`SearchDashboardsInput`](crate::operation::search_dashboards::SearchDashboardsInput).
    pub fn builder() -> crate::operation::search_dashboards::builders::SearchDashboardsInputBuilder {
        crate::operation::search_dashboards::builders::SearchDashboardsInputBuilder::default()
    }
}

/// A builder for [`SearchDashboardsInput`](crate::operation::search_dashboards::SearchDashboardsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchDashboardsInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::DashboardSearchFilter>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl SearchDashboardsInputBuilder {
    /// <p>The ID of the Amazon Web Services account that contains the user whose dashboards you're searching for.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the user whose dashboards you're searching for.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the user whose dashboards you're searching for.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>The filters to apply to the search. Currently, you can search only by user name, for example, <code>"Filters": \[ { "Name": "QUICKSIGHT_USER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1" } \]</code></p>
    pub fn filters(mut self, input: crate::types::DashboardSearchFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The filters to apply to the search. Currently, you can search only by user name, for example, <code>"Filters": \[ { "Name": "QUICKSIGHT_USER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1" } \]</code></p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DashboardSearchFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>The filters to apply to the search. Currently, you can search only by user name, for example, <code>"Filters": \[ { "Name": "QUICKSIGHT_USER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1" } \]</code></p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DashboardSearchFilter>> {
        &self.filters
    }
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`SearchDashboardsInput`](crate::operation::search_dashboards::SearchDashboardsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::search_dashboards::SearchDashboardsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::search_dashboards::SearchDashboardsInput {
            aws_account_id: self.aws_account_id,
            filters: self.filters,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}

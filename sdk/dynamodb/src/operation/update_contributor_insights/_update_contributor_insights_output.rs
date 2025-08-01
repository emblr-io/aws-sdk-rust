// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateContributorInsightsOutput {
    /// <p>The name of the table.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the global secondary index, if applicable.</p>
    pub index_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of contributor insights</p>
    pub contributor_insights_status: ::std::option::Option<crate::types::ContributorInsightsStatus>,
    _request_id: Option<String>,
}
impl UpdateContributorInsightsOutput {
    /// <p>The name of the table.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>The name of the global secondary index, if applicable.</p>
    pub fn index_name(&self) -> ::std::option::Option<&str> {
        self.index_name.as_deref()
    }
    /// <p>The status of contributor insights</p>
    pub fn contributor_insights_status(&self) -> ::std::option::Option<&crate::types::ContributorInsightsStatus> {
        self.contributor_insights_status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateContributorInsightsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateContributorInsightsOutput {
    /// Creates a new builder-style object to manufacture [`UpdateContributorInsightsOutput`](crate::operation::update_contributor_insights::UpdateContributorInsightsOutput).
    pub fn builder() -> crate::operation::update_contributor_insights::builders::UpdateContributorInsightsOutputBuilder {
        crate::operation::update_contributor_insights::builders::UpdateContributorInsightsOutputBuilder::default()
    }
}

/// A builder for [`UpdateContributorInsightsOutput`](crate::operation::update_contributor_insights::UpdateContributorInsightsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateContributorInsightsOutputBuilder {
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) index_name: ::std::option::Option<::std::string::String>,
    pub(crate) contributor_insights_status: ::std::option::Option<crate::types::ContributorInsightsStatus>,
    _request_id: Option<String>,
}
impl UpdateContributorInsightsOutputBuilder {
    /// <p>The name of the table.</p>
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the table.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>The name of the global secondary index, if applicable.</p>
    pub fn index_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the global secondary index, if applicable.</p>
    pub fn set_index_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_name = input;
        self
    }
    /// <p>The name of the global secondary index, if applicable.</p>
    pub fn get_index_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_name
    }
    /// <p>The status of contributor insights</p>
    pub fn contributor_insights_status(mut self, input: crate::types::ContributorInsightsStatus) -> Self {
        self.contributor_insights_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of contributor insights</p>
    pub fn set_contributor_insights_status(mut self, input: ::std::option::Option<crate::types::ContributorInsightsStatus>) -> Self {
        self.contributor_insights_status = input;
        self
    }
    /// <p>The status of contributor insights</p>
    pub fn get_contributor_insights_status(&self) -> &::std::option::Option<crate::types::ContributorInsightsStatus> {
        &self.contributor_insights_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateContributorInsightsOutput`](crate::operation::update_contributor_insights::UpdateContributorInsightsOutput).
    pub fn build(self) -> crate::operation::update_contributor_insights::UpdateContributorInsightsOutput {
        crate::operation::update_contributor_insights::UpdateContributorInsightsOutput {
            table_name: self.table_name,
            index_name: self.index_name,
            contributor_insights_status: self.contributor_insights_status,
            _request_id: self._request_id,
        }
    }
}

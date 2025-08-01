// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetUsageStatisticsOutput {
    /// <p>The usage statistics object. If a UsageStatisticType was provided, the objects representing other types will be null.</p>
    pub usage_statistics: ::std::option::Option<crate::types::UsageStatistics>,
    /// <p>The pagination parameter to be used on the next list operation to retrieve more items.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetUsageStatisticsOutput {
    /// <p>The usage statistics object. If a UsageStatisticType was provided, the objects representing other types will be null.</p>
    pub fn usage_statistics(&self) -> ::std::option::Option<&crate::types::UsageStatistics> {
        self.usage_statistics.as_ref()
    }
    /// <p>The pagination parameter to be used on the next list operation to retrieve more items.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetUsageStatisticsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetUsageStatisticsOutput {
    /// Creates a new builder-style object to manufacture [`GetUsageStatisticsOutput`](crate::operation::get_usage_statistics::GetUsageStatisticsOutput).
    pub fn builder() -> crate::operation::get_usage_statistics::builders::GetUsageStatisticsOutputBuilder {
        crate::operation::get_usage_statistics::builders::GetUsageStatisticsOutputBuilder::default()
    }
}

/// A builder for [`GetUsageStatisticsOutput`](crate::operation::get_usage_statistics::GetUsageStatisticsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetUsageStatisticsOutputBuilder {
    pub(crate) usage_statistics: ::std::option::Option<crate::types::UsageStatistics>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetUsageStatisticsOutputBuilder {
    /// <p>The usage statistics object. If a UsageStatisticType was provided, the objects representing other types will be null.</p>
    pub fn usage_statistics(mut self, input: crate::types::UsageStatistics) -> Self {
        self.usage_statistics = ::std::option::Option::Some(input);
        self
    }
    /// <p>The usage statistics object. If a UsageStatisticType was provided, the objects representing other types will be null.</p>
    pub fn set_usage_statistics(mut self, input: ::std::option::Option<crate::types::UsageStatistics>) -> Self {
        self.usage_statistics = input;
        self
    }
    /// <p>The usage statistics object. If a UsageStatisticType was provided, the objects representing other types will be null.</p>
    pub fn get_usage_statistics(&self) -> &::std::option::Option<crate::types::UsageStatistics> {
        &self.usage_statistics
    }
    /// <p>The pagination parameter to be used on the next list operation to retrieve more items.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination parameter to be used on the next list operation to retrieve more items.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination parameter to be used on the next list operation to retrieve more items.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetUsageStatisticsOutput`](crate::operation::get_usage_statistics::GetUsageStatisticsOutput).
    pub fn build(self) -> crate::operation::get_usage_statistics::GetUsageStatisticsOutput {
        crate::operation::get_usage_statistics::GetUsageStatisticsOutput {
            usage_statistics: self.usage_statistics,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

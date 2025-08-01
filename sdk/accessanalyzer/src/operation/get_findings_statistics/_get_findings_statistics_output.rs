// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFindingsStatisticsOutput {
    /// <p>A group of external access or unused access findings statistics.</p>
    pub findings_statistics: ::std::option::Option<::std::vec::Vec<crate::types::FindingsStatistics>>,
    /// <p>The time at which the retrieval of the findings statistics was last updated. If the findings statistics have not been previously retrieved for the specified analyzer, this field will not be populated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetFindingsStatisticsOutput {
    /// <p>A group of external access or unused access findings statistics.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.findings_statistics.is_none()`.
    pub fn findings_statistics(&self) -> &[crate::types::FindingsStatistics] {
        self.findings_statistics.as_deref().unwrap_or_default()
    }
    /// <p>The time at which the retrieval of the findings statistics was last updated. If the findings statistics have not been previously retrieved for the specified analyzer, this field will not be populated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetFindingsStatisticsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFindingsStatisticsOutput {
    /// Creates a new builder-style object to manufacture [`GetFindingsStatisticsOutput`](crate::operation::get_findings_statistics::GetFindingsStatisticsOutput).
    pub fn builder() -> crate::operation::get_findings_statistics::builders::GetFindingsStatisticsOutputBuilder {
        crate::operation::get_findings_statistics::builders::GetFindingsStatisticsOutputBuilder::default()
    }
}

/// A builder for [`GetFindingsStatisticsOutput`](crate::operation::get_findings_statistics::GetFindingsStatisticsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFindingsStatisticsOutputBuilder {
    pub(crate) findings_statistics: ::std::option::Option<::std::vec::Vec<crate::types::FindingsStatistics>>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetFindingsStatisticsOutputBuilder {
    /// Appends an item to `findings_statistics`.
    ///
    /// To override the contents of this collection use [`set_findings_statistics`](Self::set_findings_statistics).
    ///
    /// <p>A group of external access or unused access findings statistics.</p>
    pub fn findings_statistics(mut self, input: crate::types::FindingsStatistics) -> Self {
        let mut v = self.findings_statistics.unwrap_or_default();
        v.push(input);
        self.findings_statistics = ::std::option::Option::Some(v);
        self
    }
    /// <p>A group of external access or unused access findings statistics.</p>
    pub fn set_findings_statistics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FindingsStatistics>>) -> Self {
        self.findings_statistics = input;
        self
    }
    /// <p>A group of external access or unused access findings statistics.</p>
    pub fn get_findings_statistics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FindingsStatistics>> {
        &self.findings_statistics
    }
    /// <p>The time at which the retrieval of the findings statistics was last updated. If the findings statistics have not been previously retrieved for the specified analyzer, this field will not be populated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the retrieval of the findings statistics was last updated. If the findings statistics have not been previously retrieved for the specified analyzer, this field will not be populated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The time at which the retrieval of the findings statistics was last updated. If the findings statistics have not been previously retrieved for the specified analyzer, this field will not be populated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFindingsStatisticsOutput`](crate::operation::get_findings_statistics::GetFindingsStatisticsOutput).
    pub fn build(self) -> crate::operation::get_findings_statistics::GetFindingsStatisticsOutput {
        crate::operation::get_findings_statistics::GetFindingsStatisticsOutput {
            findings_statistics: self.findings_statistics,
            last_updated_at: self.last_updated_at,
            _request_id: self._request_id,
        }
    }
}

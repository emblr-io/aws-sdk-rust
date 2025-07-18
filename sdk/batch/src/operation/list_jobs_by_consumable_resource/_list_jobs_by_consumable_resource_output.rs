// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListJobsByConsumableResourceOutput {
    /// <p>The list of jobs that require the specified consumable resources.</p>
    pub jobs: ::std::option::Option<::std::vec::Vec<crate::types::ListJobsByConsumableResourceSummary>>,
    /// <p>The <code>nextToken</code> value to include in a future <code>ListJobsByConsumableResource</code> request. When the results of a <code>ListJobsByConsumableResource</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListJobsByConsumableResourceOutput {
    /// <p>The list of jobs that require the specified consumable resources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.jobs.is_none()`.
    pub fn jobs(&self) -> &[crate::types::ListJobsByConsumableResourceSummary] {
        self.jobs.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>ListJobsByConsumableResource</code> request. When the results of a <code>ListJobsByConsumableResource</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListJobsByConsumableResourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListJobsByConsumableResourceOutput {
    /// Creates a new builder-style object to manufacture [`ListJobsByConsumableResourceOutput`](crate::operation::list_jobs_by_consumable_resource::ListJobsByConsumableResourceOutput).
    pub fn builder() -> crate::operation::list_jobs_by_consumable_resource::builders::ListJobsByConsumableResourceOutputBuilder {
        crate::operation::list_jobs_by_consumable_resource::builders::ListJobsByConsumableResourceOutputBuilder::default()
    }
}

/// A builder for [`ListJobsByConsumableResourceOutput`](crate::operation::list_jobs_by_consumable_resource::ListJobsByConsumableResourceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListJobsByConsumableResourceOutputBuilder {
    pub(crate) jobs: ::std::option::Option<::std::vec::Vec<crate::types::ListJobsByConsumableResourceSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListJobsByConsumableResourceOutputBuilder {
    /// Appends an item to `jobs`.
    ///
    /// To override the contents of this collection use [`set_jobs`](Self::set_jobs).
    ///
    /// <p>The list of jobs that require the specified consumable resources.</p>
    pub fn jobs(mut self, input: crate::types::ListJobsByConsumableResourceSummary) -> Self {
        let mut v = self.jobs.unwrap_or_default();
        v.push(input);
        self.jobs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of jobs that require the specified consumable resources.</p>
    pub fn set_jobs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ListJobsByConsumableResourceSummary>>) -> Self {
        self.jobs = input;
        self
    }
    /// <p>The list of jobs that require the specified consumable resources.</p>
    pub fn get_jobs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ListJobsByConsumableResourceSummary>> {
        &self.jobs
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>ListJobsByConsumableResource</code> request. When the results of a <code>ListJobsByConsumableResource</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>ListJobsByConsumableResource</code> request. When the results of a <code>ListJobsByConsumableResource</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>ListJobsByConsumableResource</code> request. When the results of a <code>ListJobsByConsumableResource</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`ListJobsByConsumableResourceOutput`](crate::operation::list_jobs_by_consumable_resource::ListJobsByConsumableResourceOutput).
    pub fn build(self) -> crate::operation::list_jobs_by_consumable_resource::ListJobsByConsumableResourceOutput {
        crate::operation::list_jobs_by_consumable_resource::ListJobsByConsumableResourceOutput {
            jobs: self.jobs,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

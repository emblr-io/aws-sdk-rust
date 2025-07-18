// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeComputeEnvironmentsOutput {
    /// <p>The list of compute environments.</p>
    pub compute_environments: ::std::option::Option<::std::vec::Vec<crate::types::ComputeEnvironmentDetail>>,
    /// <p>The <code>nextToken</code> value to include in a future <code>DescribeComputeEnvironments</code> request. When the results of a <code>DescribeComputeEnvironments</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeComputeEnvironmentsOutput {
    /// <p>The list of compute environments.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.compute_environments.is_none()`.
    pub fn compute_environments(&self) -> &[crate::types::ComputeEnvironmentDetail] {
        self.compute_environments.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>DescribeComputeEnvironments</code> request. When the results of a <code>DescribeComputeEnvironments</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeComputeEnvironmentsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeComputeEnvironmentsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeComputeEnvironmentsOutput`](crate::operation::describe_compute_environments::DescribeComputeEnvironmentsOutput).
    pub fn builder() -> crate::operation::describe_compute_environments::builders::DescribeComputeEnvironmentsOutputBuilder {
        crate::operation::describe_compute_environments::builders::DescribeComputeEnvironmentsOutputBuilder::default()
    }
}

/// A builder for [`DescribeComputeEnvironmentsOutput`](crate::operation::describe_compute_environments::DescribeComputeEnvironmentsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeComputeEnvironmentsOutputBuilder {
    pub(crate) compute_environments: ::std::option::Option<::std::vec::Vec<crate::types::ComputeEnvironmentDetail>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeComputeEnvironmentsOutputBuilder {
    /// Appends an item to `compute_environments`.
    ///
    /// To override the contents of this collection use [`set_compute_environments`](Self::set_compute_environments).
    ///
    /// <p>The list of compute environments.</p>
    pub fn compute_environments(mut self, input: crate::types::ComputeEnvironmentDetail) -> Self {
        let mut v = self.compute_environments.unwrap_or_default();
        v.push(input);
        self.compute_environments = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of compute environments.</p>
    pub fn set_compute_environments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ComputeEnvironmentDetail>>) -> Self {
        self.compute_environments = input;
        self
    }
    /// <p>The list of compute environments.</p>
    pub fn get_compute_environments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ComputeEnvironmentDetail>> {
        &self.compute_environments
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>DescribeComputeEnvironments</code> request. When the results of a <code>DescribeComputeEnvironments</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>DescribeComputeEnvironments</code> request. When the results of a <code>DescribeComputeEnvironments</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>DescribeComputeEnvironments</code> request. When the results of a <code>DescribeComputeEnvironments</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`DescribeComputeEnvironmentsOutput`](crate::operation::describe_compute_environments::DescribeComputeEnvironmentsOutput).
    pub fn build(self) -> crate::operation::describe_compute_environments::DescribeComputeEnvironmentsOutput {
        crate::operation::describe_compute_environments::DescribeComputeEnvironmentsOutput {
            compute_environments: self.compute_environments,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

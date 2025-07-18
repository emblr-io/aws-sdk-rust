// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[deprecated(
    note = "Support for the AWS RoboMaker application deployment feature has ended. For additional information, see https://docs.aws.amazon.com/robomaker/latest/dg/fleets.html."
)]
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDeploymentJobsOutput {
    /// <p>A list of deployment jobs that meet the criteria of the request.</p>
    pub deployment_jobs: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentJob>>,
    /// <p>If the previous paginated request did not return all of the remaining results, the response object's <code>nextToken</code> parameter value is set to a token. To retrieve the next set of results, call <code>ListDeploymentJobs</code> again and assign that token to the request object's <code>nextToken</code> parameter. If there are no remaining results, the previous response object's NextToken parameter is set to null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDeploymentJobsOutput {
    /// <p>A list of deployment jobs that meet the criteria of the request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.deployment_jobs.is_none()`.
    pub fn deployment_jobs(&self) -> &[crate::types::DeploymentJob] {
        self.deployment_jobs.as_deref().unwrap_or_default()
    }
    /// <p>If the previous paginated request did not return all of the remaining results, the response object's <code>nextToken</code> parameter value is set to a token. To retrieve the next set of results, call <code>ListDeploymentJobs</code> again and assign that token to the request object's <code>nextToken</code> parameter. If there are no remaining results, the previous response object's NextToken parameter is set to null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDeploymentJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDeploymentJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListDeploymentJobsOutput`](crate::operation::list_deployment_jobs::ListDeploymentJobsOutput).
    pub fn builder() -> crate::operation::list_deployment_jobs::builders::ListDeploymentJobsOutputBuilder {
        crate::operation::list_deployment_jobs::builders::ListDeploymentJobsOutputBuilder::default()
    }
}

/// A builder for [`ListDeploymentJobsOutput`](crate::operation::list_deployment_jobs::ListDeploymentJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDeploymentJobsOutputBuilder {
    pub(crate) deployment_jobs: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentJob>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDeploymentJobsOutputBuilder {
    /// Appends an item to `deployment_jobs`.
    ///
    /// To override the contents of this collection use [`set_deployment_jobs`](Self::set_deployment_jobs).
    ///
    /// <p>A list of deployment jobs that meet the criteria of the request.</p>
    pub fn deployment_jobs(mut self, input: crate::types::DeploymentJob) -> Self {
        let mut v = self.deployment_jobs.unwrap_or_default();
        v.push(input);
        self.deployment_jobs = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of deployment jobs that meet the criteria of the request.</p>
    pub fn set_deployment_jobs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentJob>>) -> Self {
        self.deployment_jobs = input;
        self
    }
    /// <p>A list of deployment jobs that meet the criteria of the request.</p>
    pub fn get_deployment_jobs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DeploymentJob>> {
        &self.deployment_jobs
    }
    /// <p>If the previous paginated request did not return all of the remaining results, the response object's <code>nextToken</code> parameter value is set to a token. To retrieve the next set of results, call <code>ListDeploymentJobs</code> again and assign that token to the request object's <code>nextToken</code> parameter. If there are no remaining results, the previous response object's NextToken parameter is set to null.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the previous paginated request did not return all of the remaining results, the response object's <code>nextToken</code> parameter value is set to a token. To retrieve the next set of results, call <code>ListDeploymentJobs</code> again and assign that token to the request object's <code>nextToken</code> parameter. If there are no remaining results, the previous response object's NextToken parameter is set to null.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the previous paginated request did not return all of the remaining results, the response object's <code>nextToken</code> parameter value is set to a token. To retrieve the next set of results, call <code>ListDeploymentJobs</code> again and assign that token to the request object's <code>nextToken</code> parameter. If there are no remaining results, the previous response object's NextToken parameter is set to null.</p>
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
    /// Consumes the builder and constructs a [`ListDeploymentJobsOutput`](crate::operation::list_deployment_jobs::ListDeploymentJobsOutput).
    pub fn build(self) -> crate::operation::list_deployment_jobs::ListDeploymentJobsOutput {
        crate::operation::list_deployment_jobs::ListDeploymentJobsOutput {
            deployment_jobs: self.deployment_jobs,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

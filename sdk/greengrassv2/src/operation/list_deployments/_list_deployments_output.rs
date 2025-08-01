// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDeploymentsOutput {
    /// <p>A list that summarizes each deployment.</p>
    pub deployments: ::std::option::Option<::std::vec::Vec<crate::types::Deployment>>,
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDeploymentsOutput {
    /// <p>A list that summarizes each deployment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.deployments.is_none()`.
    pub fn deployments(&self) -> &[crate::types::Deployment] {
        self.deployments.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDeploymentsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDeploymentsOutput {
    /// Creates a new builder-style object to manufacture [`ListDeploymentsOutput`](crate::operation::list_deployments::ListDeploymentsOutput).
    pub fn builder() -> crate::operation::list_deployments::builders::ListDeploymentsOutputBuilder {
        crate::operation::list_deployments::builders::ListDeploymentsOutputBuilder::default()
    }
}

/// A builder for [`ListDeploymentsOutput`](crate::operation::list_deployments::ListDeploymentsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDeploymentsOutputBuilder {
    pub(crate) deployments: ::std::option::Option<::std::vec::Vec<crate::types::Deployment>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDeploymentsOutputBuilder {
    /// Appends an item to `deployments`.
    ///
    /// To override the contents of this collection use [`set_deployments`](Self::set_deployments).
    ///
    /// <p>A list that summarizes each deployment.</p>
    pub fn deployments(mut self, input: crate::types::Deployment) -> Self {
        let mut v = self.deployments.unwrap_or_default();
        v.push(input);
        self.deployments = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list that summarizes each deployment.</p>
    pub fn set_deployments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Deployment>>) -> Self {
        self.deployments = input;
        self
    }
    /// <p>A list that summarizes each deployment.</p>
    pub fn get_deployments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Deployment>> {
        &self.deployments
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
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
    /// Consumes the builder and constructs a [`ListDeploymentsOutput`](crate::operation::list_deployments::ListDeploymentsOutput).
    pub fn build(self) -> crate::operation::list_deployments::ListDeploymentsOutput {
        crate::operation::list_deployments::ListDeploymentsOutput {
            deployments: self.deployments,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

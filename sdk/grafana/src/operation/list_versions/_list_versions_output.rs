// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListVersionsOutput {
    /// <p>The token to use in a subsequent <code>ListVersions</code> operation to return the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The Grafana versions available to create. If a workspace ID is included in the request, the Grafana versions to which this workspace can be upgraded.</p>
    pub grafana_versions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl ListVersionsOutput {
    /// <p>The token to use in a subsequent <code>ListVersions</code> operation to return the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The Grafana versions available to create. If a workspace ID is included in the request, the Grafana versions to which this workspace can be upgraded.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.grafana_versions.is_none()`.
    pub fn grafana_versions(&self) -> &[::std::string::String] {
        self.grafana_versions.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListVersionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListVersionsOutput {
    /// Creates a new builder-style object to manufacture [`ListVersionsOutput`](crate::operation::list_versions::ListVersionsOutput).
    pub fn builder() -> crate::operation::list_versions::builders::ListVersionsOutputBuilder {
        crate::operation::list_versions::builders::ListVersionsOutputBuilder::default()
    }
}

/// A builder for [`ListVersionsOutput`](crate::operation::list_versions::ListVersionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListVersionsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) grafana_versions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl ListVersionsOutputBuilder {
    /// <p>The token to use in a subsequent <code>ListVersions</code> operation to return the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use in a subsequent <code>ListVersions</code> operation to return the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use in a subsequent <code>ListVersions</code> operation to return the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `grafana_versions`.
    ///
    /// To override the contents of this collection use [`set_grafana_versions`](Self::set_grafana_versions).
    ///
    /// <p>The Grafana versions available to create. If a workspace ID is included in the request, the Grafana versions to which this workspace can be upgraded.</p>
    pub fn grafana_versions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.grafana_versions.unwrap_or_default();
        v.push(input.into());
        self.grafana_versions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Grafana versions available to create. If a workspace ID is included in the request, the Grafana versions to which this workspace can be upgraded.</p>
    pub fn set_grafana_versions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.grafana_versions = input;
        self
    }
    /// <p>The Grafana versions available to create. If a workspace ID is included in the request, the Grafana versions to which this workspace can be upgraded.</p>
    pub fn get_grafana_versions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.grafana_versions
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListVersionsOutput`](crate::operation::list_versions::ListVersionsOutput).
    pub fn build(self) -> crate::operation::list_versions::ListVersionsOutput {
        crate::operation::list_versions::ListVersionsOutput {
            next_token: self.next_token,
            grafana_versions: self.grafana_versions,
            _request_id: self._request_id,
        }
    }
}

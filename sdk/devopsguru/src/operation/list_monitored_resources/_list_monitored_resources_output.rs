// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMonitoredResourcesOutput {
    /// <p>Information about the resource that is being monitored, including the name of the resource, the type of resource, and whether or not permission is given to DevOps Guru to access that resource.</p>
    pub monitored_resource_identifiers: ::std::vec::Vec<crate::types::MonitoredResourceIdentifier>,
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMonitoredResourcesOutput {
    /// <p>Information about the resource that is being monitored, including the name of the resource, the type of resource, and whether or not permission is given to DevOps Guru to access that resource.</p>
    pub fn monitored_resource_identifiers(&self) -> &[crate::types::MonitoredResourceIdentifier] {
        use std::ops::Deref;
        self.monitored_resource_identifiers.deref()
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListMonitoredResourcesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListMonitoredResourcesOutput {
    /// Creates a new builder-style object to manufacture [`ListMonitoredResourcesOutput`](crate::operation::list_monitored_resources::ListMonitoredResourcesOutput).
    pub fn builder() -> crate::operation::list_monitored_resources::builders::ListMonitoredResourcesOutputBuilder {
        crate::operation::list_monitored_resources::builders::ListMonitoredResourcesOutputBuilder::default()
    }
}

/// A builder for [`ListMonitoredResourcesOutput`](crate::operation::list_monitored_resources::ListMonitoredResourcesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMonitoredResourcesOutputBuilder {
    pub(crate) monitored_resource_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::MonitoredResourceIdentifier>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMonitoredResourcesOutputBuilder {
    /// Appends an item to `monitored_resource_identifiers`.
    ///
    /// To override the contents of this collection use [`set_monitored_resource_identifiers`](Self::set_monitored_resource_identifiers).
    ///
    /// <p>Information about the resource that is being monitored, including the name of the resource, the type of resource, and whether or not permission is given to DevOps Guru to access that resource.</p>
    pub fn monitored_resource_identifiers(mut self, input: crate::types::MonitoredResourceIdentifier) -> Self {
        let mut v = self.monitored_resource_identifiers.unwrap_or_default();
        v.push(input);
        self.monitored_resource_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the resource that is being monitored, including the name of the resource, the type of resource, and whether or not permission is given to DevOps Guru to access that resource.</p>
    pub fn set_monitored_resource_identifiers(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::MonitoredResourceIdentifier>>,
    ) -> Self {
        self.monitored_resource_identifiers = input;
        self
    }
    /// <p>Information about the resource that is being monitored, including the name of the resource, the type of resource, and whether or not permission is given to DevOps Guru to access that resource.</p>
    pub fn get_monitored_resource_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MonitoredResourceIdentifier>> {
        &self.monitored_resource_identifiers
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If there are no more pages, this value is null.</p>
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
    /// Consumes the builder and constructs a [`ListMonitoredResourcesOutput`](crate::operation::list_monitored_resources::ListMonitoredResourcesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`monitored_resource_identifiers`](crate::operation::list_monitored_resources::builders::ListMonitoredResourcesOutputBuilder::monitored_resource_identifiers)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_monitored_resources::ListMonitoredResourcesOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_monitored_resources::ListMonitoredResourcesOutput {
            monitored_resource_identifiers: self.monitored_resource_identifiers.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "monitored_resource_identifiers",
                    "monitored_resource_identifiers was not specified but it is required when building ListMonitoredResourcesOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}

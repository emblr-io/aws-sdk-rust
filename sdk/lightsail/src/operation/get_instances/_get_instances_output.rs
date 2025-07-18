// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInstancesOutput {
    /// <p>An array of key-value pairs containing information about your instances.</p>
    pub instances: ::std::option::Option<::std::vec::Vec<crate::types::Instance>>,
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetInstances</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetInstancesOutput {
    /// <p>An array of key-value pairs containing information about your instances.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instances.is_none()`.
    pub fn instances(&self) -> &[crate::types::Instance] {
        self.instances.as_deref().unwrap_or_default()
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetInstances</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetInstancesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetInstancesOutput {
    /// Creates a new builder-style object to manufacture [`GetInstancesOutput`](crate::operation::get_instances::GetInstancesOutput).
    pub fn builder() -> crate::operation::get_instances::builders::GetInstancesOutputBuilder {
        crate::operation::get_instances::builders::GetInstancesOutputBuilder::default()
    }
}

/// A builder for [`GetInstancesOutput`](crate::operation::get_instances::GetInstancesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInstancesOutputBuilder {
    pub(crate) instances: ::std::option::Option<::std::vec::Vec<crate::types::Instance>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetInstancesOutputBuilder {
    /// Appends an item to `instances`.
    ///
    /// To override the contents of this collection use [`set_instances`](Self::set_instances).
    ///
    /// <p>An array of key-value pairs containing information about your instances.</p>
    pub fn instances(mut self, input: crate::types::Instance) -> Self {
        let mut v = self.instances.unwrap_or_default();
        v.push(input);
        self.instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of key-value pairs containing information about your instances.</p>
    pub fn set_instances(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Instance>>) -> Self {
        self.instances = input;
        self
    }
    /// <p>An array of key-value pairs containing information about your instances.</p>
    pub fn get_instances(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Instance>> {
        &self.instances
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetInstances</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetInstances</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetInstances</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetInstancesOutput`](crate::operation::get_instances::GetInstancesOutput).
    pub fn build(self) -> crate::operation::get_instances::GetInstancesOutput {
        crate::operation::get_instances::GetInstancesOutput {
            instances: self.instances,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}

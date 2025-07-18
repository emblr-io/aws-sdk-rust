// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListConnectionGroupsOutput {
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    /// <p>The list of connection groups that you retrieved.</p>
    pub connection_groups: ::std::option::Option<::std::vec::Vec<crate::types::ConnectionGroupSummary>>,
    _request_id: Option<String>,
}
impl ListConnectionGroupsOutput {
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
    /// <p>The list of connection groups that you retrieved.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.connection_groups.is_none()`.
    pub fn connection_groups(&self) -> &[crate::types::ConnectionGroupSummary] {
        self.connection_groups.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListConnectionGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListConnectionGroupsOutput {
    /// Creates a new builder-style object to manufacture [`ListConnectionGroupsOutput`](crate::operation::list_connection_groups::ListConnectionGroupsOutput).
    pub fn builder() -> crate::operation::list_connection_groups::builders::ListConnectionGroupsOutputBuilder {
        crate::operation::list_connection_groups::builders::ListConnectionGroupsOutputBuilder::default()
    }
}

/// A builder for [`ListConnectionGroupsOutput`](crate::operation::list_connection_groups::ListConnectionGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListConnectionGroupsOutputBuilder {
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    pub(crate) connection_groups: ::std::option::Option<::std::vec::Vec<crate::types::ConnectionGroupSummary>>,
    _request_id: Option<String>,
}
impl ListConnectionGroupsOutputBuilder {
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    /// Appends an item to `connection_groups`.
    ///
    /// To override the contents of this collection use [`set_connection_groups`](Self::set_connection_groups).
    ///
    /// <p>The list of connection groups that you retrieved.</p>
    pub fn connection_groups(mut self, input: crate::types::ConnectionGroupSummary) -> Self {
        let mut v = self.connection_groups.unwrap_or_default();
        v.push(input);
        self.connection_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of connection groups that you retrieved.</p>
    pub fn set_connection_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConnectionGroupSummary>>) -> Self {
        self.connection_groups = input;
        self
    }
    /// <p>The list of connection groups that you retrieved.</p>
    pub fn get_connection_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConnectionGroupSummary>> {
        &self.connection_groups
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListConnectionGroupsOutput`](crate::operation::list_connection_groups::ListConnectionGroupsOutput).
    pub fn build(self) -> crate::operation::list_connection_groups::ListConnectionGroupsOutput {
        crate::operation::list_connection_groups::ListConnectionGroupsOutput {
            next_marker: self.next_marker,
            connection_groups: self.connection_groups,
            _request_id: self._request_id,
        }
    }
}

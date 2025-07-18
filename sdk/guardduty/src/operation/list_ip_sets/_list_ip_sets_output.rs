// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListIpSetsOutput {
    /// <p>The IDs of the IPSet resources.</p>
    pub ip_set_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The pagination parameter to be used on the next list operation to retrieve more items.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListIpSetsOutput {
    /// <p>The IDs of the IPSet resources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ip_set_ids.is_none()`.
    pub fn ip_set_ids(&self) -> &[::std::string::String] {
        self.ip_set_ids.as_deref().unwrap_or_default()
    }
    /// <p>The pagination parameter to be used on the next list operation to retrieve more items.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListIpSetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListIpSetsOutput {
    /// Creates a new builder-style object to manufacture [`ListIpSetsOutput`](crate::operation::list_ip_sets::ListIpSetsOutput).
    pub fn builder() -> crate::operation::list_ip_sets::builders::ListIpSetsOutputBuilder {
        crate::operation::list_ip_sets::builders::ListIpSetsOutputBuilder::default()
    }
}

/// A builder for [`ListIpSetsOutput`](crate::operation::list_ip_sets::ListIpSetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListIpSetsOutputBuilder {
    pub(crate) ip_set_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListIpSetsOutputBuilder {
    /// Appends an item to `ip_set_ids`.
    ///
    /// To override the contents of this collection use [`set_ip_set_ids`](Self::set_ip_set_ids).
    ///
    /// <p>The IDs of the IPSet resources.</p>
    pub fn ip_set_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ip_set_ids.unwrap_or_default();
        v.push(input.into());
        self.ip_set_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the IPSet resources.</p>
    pub fn set_ip_set_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ip_set_ids = input;
        self
    }
    /// <p>The IDs of the IPSet resources.</p>
    pub fn get_ip_set_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ip_set_ids
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
    /// Consumes the builder and constructs a [`ListIpSetsOutput`](crate::operation::list_ip_sets::ListIpSetsOutput).
    pub fn build(self) -> crate::operation::list_ip_sets::ListIpSetsOutput {
        crate::operation::list_ip_sets::ListIpSetsOutput {
            ip_set_ids: self.ip_set_ids,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

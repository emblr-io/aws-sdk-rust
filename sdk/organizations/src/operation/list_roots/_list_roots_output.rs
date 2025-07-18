// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRootsOutput {
    /// <p>A list of roots that are defined in an organization.</p>
    pub roots: ::std::option::Option<::std::vec::Vec<crate::types::Root>>,
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRootsOutput {
    /// <p>A list of roots that are defined in an organization.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.roots.is_none()`.
    pub fn roots(&self) -> &[crate::types::Root] {
        self.roots.as_deref().unwrap_or_default()
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRootsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRootsOutput {
    /// Creates a new builder-style object to manufacture [`ListRootsOutput`](crate::operation::list_roots::ListRootsOutput).
    pub fn builder() -> crate::operation::list_roots::builders::ListRootsOutputBuilder {
        crate::operation::list_roots::builders::ListRootsOutputBuilder::default()
    }
}

/// A builder for [`ListRootsOutput`](crate::operation::list_roots::ListRootsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRootsOutputBuilder {
    pub(crate) roots: ::std::option::Option<::std::vec::Vec<crate::types::Root>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRootsOutputBuilder {
    /// Appends an item to `roots`.
    ///
    /// To override the contents of this collection use [`set_roots`](Self::set_roots).
    ///
    /// <p>A list of roots that are defined in an organization.</p>
    pub fn roots(mut self, input: crate::types::Root) -> Self {
        let mut v = self.roots.unwrap_or_default();
        v.push(input);
        self.roots = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of roots that are defined in an organization.</p>
    pub fn set_roots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Root>>) -> Self {
        self.roots = input;
        self
    }
    /// <p>A list of roots that are defined in an organization.</p>
    pub fn get_roots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Root>> {
        &self.roots
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
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
    /// Consumes the builder and constructs a [`ListRootsOutput`](crate::operation::list_roots::ListRootsOutput).
    pub fn build(self) -> crate::operation::list_roots::ListRootsOutput {
        crate::operation::list_roots::ListRootsOutput {
            roots: self.roots,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

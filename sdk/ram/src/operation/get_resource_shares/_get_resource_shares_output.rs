// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourceSharesOutput {
    /// <p>An array of objects that contain the information about the resource shares.</p>
    pub resource_shares: ::std::option::Option<::std::vec::Vec<crate::types::ResourceShare>>,
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourceSharesOutput {
    /// <p>An array of objects that contain the information about the resource shares.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_shares.is_none()`.
    pub fn resource_shares(&self) -> &[crate::types::ResourceShare] {
        self.resource_shares.as_deref().unwrap_or_default()
    }
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetResourceSharesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetResourceSharesOutput {
    /// Creates a new builder-style object to manufacture [`GetResourceSharesOutput`](crate::operation::get_resource_shares::GetResourceSharesOutput).
    pub fn builder() -> crate::operation::get_resource_shares::builders::GetResourceSharesOutputBuilder {
        crate::operation::get_resource_shares::builders::GetResourceSharesOutputBuilder::default()
    }
}

/// A builder for [`GetResourceSharesOutput`](crate::operation::get_resource_shares::GetResourceSharesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourceSharesOutputBuilder {
    pub(crate) resource_shares: ::std::option::Option<::std::vec::Vec<crate::types::ResourceShare>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourceSharesOutputBuilder {
    /// Appends an item to `resource_shares`.
    ///
    /// To override the contents of this collection use [`set_resource_shares`](Self::set_resource_shares).
    ///
    /// <p>An array of objects that contain the information about the resource shares.</p>
    pub fn resource_shares(mut self, input: crate::types::ResourceShare) -> Self {
        let mut v = self.resource_shares.unwrap_or_default();
        v.push(input);
        self.resource_shares = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that contain the information about the resource shares.</p>
    pub fn set_resource_shares(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceShare>>) -> Self {
        self.resource_shares = input;
        self
    }
    /// <p>An array of objects that contain the information about the resource shares.</p>
    pub fn get_resource_shares(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceShare>> {
        &self.resource_shares
    }
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If present, this value indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>. This indicates that this is the last page of results.</p>
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
    /// Consumes the builder and constructs a [`GetResourceSharesOutput`](crate::operation::get_resource_shares::GetResourceSharesOutput).
    pub fn build(self) -> crate::operation::get_resource_shares::GetResourceSharesOutput {
        crate::operation::get_resource_shares::GetResourceSharesOutput {
            resource_shares: self.resource_shares,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

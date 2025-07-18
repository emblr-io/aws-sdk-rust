// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of all of the identities that you've attempted to verify for use with Amazon Pinpoint, regardless of whether or not those identities were successfully verified.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEmailIdentitiesOutput {
    /// <p>An array that includes all of the identities associated with your Amazon Pinpoint account.</p>
    pub email_identities: ::std::option::Option<::std::vec::Vec<crate::types::IdentityInfo>>,
    /// <p>A token that indicates that there are additional configuration sets to list. To view additional configuration sets, issue another request to <code>ListEmailIdentities</code>, and pass this token in the <code>NextToken</code> parameter.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListEmailIdentitiesOutput {
    /// <p>An array that includes all of the identities associated with your Amazon Pinpoint account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.email_identities.is_none()`.
    pub fn email_identities(&self) -> &[crate::types::IdentityInfo] {
        self.email_identities.as_deref().unwrap_or_default()
    }
    /// <p>A token that indicates that there are additional configuration sets to list. To view additional configuration sets, issue another request to <code>ListEmailIdentities</code>, and pass this token in the <code>NextToken</code> parameter.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListEmailIdentitiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListEmailIdentitiesOutput {
    /// Creates a new builder-style object to manufacture [`ListEmailIdentitiesOutput`](crate::operation::list_email_identities::ListEmailIdentitiesOutput).
    pub fn builder() -> crate::operation::list_email_identities::builders::ListEmailIdentitiesOutputBuilder {
        crate::operation::list_email_identities::builders::ListEmailIdentitiesOutputBuilder::default()
    }
}

/// A builder for [`ListEmailIdentitiesOutput`](crate::operation::list_email_identities::ListEmailIdentitiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEmailIdentitiesOutputBuilder {
    pub(crate) email_identities: ::std::option::Option<::std::vec::Vec<crate::types::IdentityInfo>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListEmailIdentitiesOutputBuilder {
    /// Appends an item to `email_identities`.
    ///
    /// To override the contents of this collection use [`set_email_identities`](Self::set_email_identities).
    ///
    /// <p>An array that includes all of the identities associated with your Amazon Pinpoint account.</p>
    pub fn email_identities(mut self, input: crate::types::IdentityInfo) -> Self {
        let mut v = self.email_identities.unwrap_or_default();
        v.push(input);
        self.email_identities = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array that includes all of the identities associated with your Amazon Pinpoint account.</p>
    pub fn set_email_identities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IdentityInfo>>) -> Self {
        self.email_identities = input;
        self
    }
    /// <p>An array that includes all of the identities associated with your Amazon Pinpoint account.</p>
    pub fn get_email_identities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IdentityInfo>> {
        &self.email_identities
    }
    /// <p>A token that indicates that there are additional configuration sets to list. To view additional configuration sets, issue another request to <code>ListEmailIdentities</code>, and pass this token in the <code>NextToken</code> parameter.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates that there are additional configuration sets to list. To view additional configuration sets, issue another request to <code>ListEmailIdentities</code>, and pass this token in the <code>NextToken</code> parameter.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates that there are additional configuration sets to list. To view additional configuration sets, issue another request to <code>ListEmailIdentities</code>, and pass this token in the <code>NextToken</code> parameter.</p>
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
    /// Consumes the builder and constructs a [`ListEmailIdentitiesOutput`](crate::operation::list_email_identities::ListEmailIdentitiesOutput).
    pub fn build(self) -> crate::operation::list_email_identities::ListEmailIdentitiesOutput {
        crate::operation::list_email_identities::ListEmailIdentitiesOutput {
            email_identities: self.email_identities,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

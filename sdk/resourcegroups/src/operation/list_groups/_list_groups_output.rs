// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListGroupsOutput {
    /// <p>A list of <code>GroupIdentifier</code> objects. Each identifier is an object that contains both the <code>Name</code> and the <code>GroupArn</code>.</p>
    pub group_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::GroupIdentifier>>,
    /// <important>
    /// <p><i> <b>Deprecated - don't use this field. Use the <code>GroupIdentifiers</code> response field instead.</b> </i></p>
    /// </important>
    #[deprecated(note = "This field is deprecated, use GroupIdentifiers instead.")]
    pub groups: ::std::option::Option<::std::vec::Vec<crate::types::Group>>,
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListGroupsOutput {
    /// <p>A list of <code>GroupIdentifier</code> objects. Each identifier is an object that contains both the <code>Name</code> and the <code>GroupArn</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.group_identifiers.is_none()`.
    pub fn group_identifiers(&self) -> &[crate::types::GroupIdentifier] {
        self.group_identifiers.as_deref().unwrap_or_default()
    }
    /// <important>
    /// <p><i> <b>Deprecated - don't use this field. Use the <code>GroupIdentifiers</code> response field instead.</b> </i></p>
    /// </important>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.groups.is_none()`.
    #[deprecated(note = "This field is deprecated, use GroupIdentifiers instead.")]
    pub fn groups(&self) -> &[crate::types::Group] {
        self.groups.as_deref().unwrap_or_default()
    }
    /// <p>If present, indicates that more output is available than is included in the current response. Use this value in the <code>NextToken</code> request parameter in a subsequent call to the operation to get the next part of the output. You should repeat this until the <code>NextToken</code> response element comes back as <code>null</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListGroupsOutput {
    /// Creates a new builder-style object to manufacture [`ListGroupsOutput`](crate::operation::list_groups::ListGroupsOutput).
    pub fn builder() -> crate::operation::list_groups::builders::ListGroupsOutputBuilder {
        crate::operation::list_groups::builders::ListGroupsOutputBuilder::default()
    }
}

/// A builder for [`ListGroupsOutput`](crate::operation::list_groups::ListGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListGroupsOutputBuilder {
    pub(crate) group_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::GroupIdentifier>>,
    pub(crate) groups: ::std::option::Option<::std::vec::Vec<crate::types::Group>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListGroupsOutputBuilder {
    /// Appends an item to `group_identifiers`.
    ///
    /// To override the contents of this collection use [`set_group_identifiers`](Self::set_group_identifiers).
    ///
    /// <p>A list of <code>GroupIdentifier</code> objects. Each identifier is an object that contains both the <code>Name</code> and the <code>GroupArn</code>.</p>
    pub fn group_identifiers(mut self, input: crate::types::GroupIdentifier) -> Self {
        let mut v = self.group_identifiers.unwrap_or_default();
        v.push(input);
        self.group_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>GroupIdentifier</code> objects. Each identifier is an object that contains both the <code>Name</code> and the <code>GroupArn</code>.</p>
    pub fn set_group_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GroupIdentifier>>) -> Self {
        self.group_identifiers = input;
        self
    }
    /// <p>A list of <code>GroupIdentifier</code> objects. Each identifier is an object that contains both the <code>Name</code> and the <code>GroupArn</code>.</p>
    pub fn get_group_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GroupIdentifier>> {
        &self.group_identifiers
    }
    /// Appends an item to `groups`.
    ///
    /// To override the contents of this collection use [`set_groups`](Self::set_groups).
    ///
    /// <important>
    /// <p><i> <b>Deprecated - don't use this field. Use the <code>GroupIdentifiers</code> response field instead.</b> </i></p>
    /// </important>
    #[deprecated(note = "This field is deprecated, use GroupIdentifiers instead.")]
    pub fn groups(mut self, input: crate::types::Group) -> Self {
        let mut v = self.groups.unwrap_or_default();
        v.push(input);
        self.groups = ::std::option::Option::Some(v);
        self
    }
    /// <important>
    /// <p><i> <b>Deprecated - don't use this field. Use the <code>GroupIdentifiers</code> response field instead.</b> </i></p>
    /// </important>
    #[deprecated(note = "This field is deprecated, use GroupIdentifiers instead.")]
    pub fn set_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Group>>) -> Self {
        self.groups = input;
        self
    }
    /// <important>
    /// <p><i> <b>Deprecated - don't use this field. Use the <code>GroupIdentifiers</code> response field instead.</b> </i></p>
    /// </important>
    #[deprecated(note = "This field is deprecated, use GroupIdentifiers instead.")]
    pub fn get_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Group>> {
        &self.groups
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
    /// Consumes the builder and constructs a [`ListGroupsOutput`](crate::operation::list_groups::ListGroupsOutput).
    pub fn build(self) -> crate::operation::list_groups::ListGroupsOutput {
        crate::operation::list_groups::ListGroupsOutput {
            group_identifiers: self.group_identifiers,
            groups: self.groups,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

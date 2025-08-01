// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetManagedPrefixListAssociationsOutput {
    /// <p>Information about the associations.</p>
    pub prefix_list_associations: ::std::option::Option<::std::vec::Vec<crate::types::PrefixListAssociation>>,
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetManagedPrefixListAssociationsOutput {
    /// <p>Information about the associations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.prefix_list_associations.is_none()`.
    pub fn prefix_list_associations(&self) -> &[crate::types::PrefixListAssociation] {
        self.prefix_list_associations.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetManagedPrefixListAssociationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetManagedPrefixListAssociationsOutput {
    /// Creates a new builder-style object to manufacture [`GetManagedPrefixListAssociationsOutput`](crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsOutput).
    pub fn builder() -> crate::operation::get_managed_prefix_list_associations::builders::GetManagedPrefixListAssociationsOutputBuilder {
        crate::operation::get_managed_prefix_list_associations::builders::GetManagedPrefixListAssociationsOutputBuilder::default()
    }
}

/// A builder for [`GetManagedPrefixListAssociationsOutput`](crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetManagedPrefixListAssociationsOutputBuilder {
    pub(crate) prefix_list_associations: ::std::option::Option<::std::vec::Vec<crate::types::PrefixListAssociation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetManagedPrefixListAssociationsOutputBuilder {
    /// Appends an item to `prefix_list_associations`.
    ///
    /// To override the contents of this collection use [`set_prefix_list_associations`](Self::set_prefix_list_associations).
    ///
    /// <p>Information about the associations.</p>
    pub fn prefix_list_associations(mut self, input: crate::types::PrefixListAssociation) -> Self {
        let mut v = self.prefix_list_associations.unwrap_or_default();
        v.push(input);
        self.prefix_list_associations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the associations.</p>
    pub fn set_prefix_list_associations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PrefixListAssociation>>) -> Self {
        self.prefix_list_associations = input;
        self
    }
    /// <p>Information about the associations.</p>
    pub fn get_prefix_list_associations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PrefixListAssociation>> {
        &self.prefix_list_associations
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`GetManagedPrefixListAssociationsOutput`](crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsOutput).
    pub fn build(self) -> crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsOutput {
        crate::operation::get_managed_prefix_list_associations::GetManagedPrefixListAssociationsOutput {
            prefix_list_associations: self.prefix_list_associations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

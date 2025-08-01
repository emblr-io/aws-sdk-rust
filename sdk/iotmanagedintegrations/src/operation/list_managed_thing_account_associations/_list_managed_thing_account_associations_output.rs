// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListManagedThingAccountAssociationsOutput {
    /// <p>The list of managed thing associations that match the specified criteria, including the managed thing ID and account association ID for each association.</p>
    pub items: ::std::option::Option<::std::vec::Vec<crate::types::ManagedThingAssociation>>,
    /// <p>A token used for pagination of results when there are more account associations than can be returned in a single response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListManagedThingAccountAssociationsOutput {
    /// <p>The list of managed thing associations that match the specified criteria, including the managed thing ID and account association ID for each association.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[crate::types::ManagedThingAssociation] {
        self.items.as_deref().unwrap_or_default()
    }
    /// <p>A token used for pagination of results when there are more account associations than can be returned in a single response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListManagedThingAccountAssociationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListManagedThingAccountAssociationsOutput {
    /// Creates a new builder-style object to manufacture [`ListManagedThingAccountAssociationsOutput`](crate::operation::list_managed_thing_account_associations::ListManagedThingAccountAssociationsOutput).
    pub fn builder() -> crate::operation::list_managed_thing_account_associations::builders::ListManagedThingAccountAssociationsOutputBuilder {
        crate::operation::list_managed_thing_account_associations::builders::ListManagedThingAccountAssociationsOutputBuilder::default()
    }
}

/// A builder for [`ListManagedThingAccountAssociationsOutput`](crate::operation::list_managed_thing_account_associations::ListManagedThingAccountAssociationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListManagedThingAccountAssociationsOutputBuilder {
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::ManagedThingAssociation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListManagedThingAccountAssociationsOutputBuilder {
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>The list of managed thing associations that match the specified criteria, including the managed thing ID and account association ID for each association.</p>
    pub fn items(mut self, input: crate::types::ManagedThingAssociation) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of managed thing associations that match the specified criteria, including the managed thing ID and account association ID for each association.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ManagedThingAssociation>>) -> Self {
        self.items = input;
        self
    }
    /// <p>The list of managed thing associations that match the specified criteria, including the managed thing ID and account association ID for each association.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ManagedThingAssociation>> {
        &self.items
    }
    /// <p>A token used for pagination of results when there are more account associations than can be returned in a single response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token used for pagination of results when there are more account associations than can be returned in a single response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token used for pagination of results when there are more account associations than can be returned in a single response.</p>
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
    /// Consumes the builder and constructs a [`ListManagedThingAccountAssociationsOutput`](crate::operation::list_managed_thing_account_associations::ListManagedThingAccountAssociationsOutput).
    pub fn build(self) -> crate::operation::list_managed_thing_account_associations::ListManagedThingAccountAssociationsOutput {
        crate::operation::list_managed_thing_account_associations::ListManagedThingAccountAssociationsOutput {
            items: self.items,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}

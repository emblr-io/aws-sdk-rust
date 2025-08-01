// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Input to the UnlinkIdentity action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnlinkIdentityInput {
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub identity_id: ::std::option::Option<::std::string::String>,
    /// <p>A set of optional name-value pairs that map provider names to provider tokens.</p>
    pub logins: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Provider names to unlink from this identity.</p>
    pub logins_to_remove: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UnlinkIdentityInput {
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub fn identity_id(&self) -> ::std::option::Option<&str> {
        self.identity_id.as_deref()
    }
    /// <p>A set of optional name-value pairs that map provider names to provider tokens.</p>
    pub fn logins(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.logins.as_ref()
    }
    /// <p>Provider names to unlink from this identity.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.logins_to_remove.is_none()`.
    pub fn logins_to_remove(&self) -> &[::std::string::String] {
        self.logins_to_remove.as_deref().unwrap_or_default()
    }
}
impl UnlinkIdentityInput {
    /// Creates a new builder-style object to manufacture [`UnlinkIdentityInput`](crate::operation::unlink_identity::UnlinkIdentityInput).
    pub fn builder() -> crate::operation::unlink_identity::builders::UnlinkIdentityInputBuilder {
        crate::operation::unlink_identity::builders::UnlinkIdentityInputBuilder::default()
    }
}

/// A builder for [`UnlinkIdentityInput`](crate::operation::unlink_identity::UnlinkIdentityInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnlinkIdentityInputBuilder {
    pub(crate) identity_id: ::std::option::Option<::std::string::String>,
    pub(crate) logins: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) logins_to_remove: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UnlinkIdentityInputBuilder {
    /// <p>A unique identifier in the format REGION:GUID.</p>
    /// This field is required.
    pub fn identity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub fn set_identity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_id = input;
        self
    }
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub fn get_identity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_id
    }
    /// Adds a key-value pair to `logins`.
    ///
    /// To override the contents of this collection use [`set_logins`](Self::set_logins).
    ///
    /// <p>A set of optional name-value pairs that map provider names to provider tokens.</p>
    pub fn logins(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.logins.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.logins = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A set of optional name-value pairs that map provider names to provider tokens.</p>
    pub fn set_logins(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.logins = input;
        self
    }
    /// <p>A set of optional name-value pairs that map provider names to provider tokens.</p>
    pub fn get_logins(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.logins
    }
    /// Appends an item to `logins_to_remove`.
    ///
    /// To override the contents of this collection use [`set_logins_to_remove`](Self::set_logins_to_remove).
    ///
    /// <p>Provider names to unlink from this identity.</p>
    pub fn logins_to_remove(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.logins_to_remove.unwrap_or_default();
        v.push(input.into());
        self.logins_to_remove = ::std::option::Option::Some(v);
        self
    }
    /// <p>Provider names to unlink from this identity.</p>
    pub fn set_logins_to_remove(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.logins_to_remove = input;
        self
    }
    /// <p>Provider names to unlink from this identity.</p>
    pub fn get_logins_to_remove(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.logins_to_remove
    }
    /// Consumes the builder and constructs a [`UnlinkIdentityInput`](crate::operation::unlink_identity::UnlinkIdentityInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::unlink_identity::UnlinkIdentityInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::unlink_identity::UnlinkIdentityInput {
            identity_id: self.identity_id,
            logins: self.logins,
            logins_to_remove: self.logins_to_remove,
        })
    }
}

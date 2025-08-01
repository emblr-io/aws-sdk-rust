// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that defines the Key element of a ProfileObject. A Key is a special element that can be used to search for a customer profile.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ObjectTypeKey {
    /// <p>The types of keys that a ProfileObject can have. Each ProfileObject can have only 1 UNIQUE key but multiple PROFILE keys. PROFILE, ASSET, CASE, or ORDER means that this key can be used to tie an object to a PROFILE, ASSET, CASE, or ORDER respectively. UNIQUE means that it can be used to uniquely identify an object. If a key a is marked as SECONDARY, it will be used to search for profiles after all other PROFILE keys have been searched. A LOOKUP_ONLY key is only used to match a profile but is not persisted to be used for searching of the profile. A NEW_ONLY key is only used if the profile does not already exist before the object is ingested, otherwise it is only used for matching objects to profiles.</p>
    pub standard_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::StandardIdentifier>>,
    /// <p>The reference for the key name of the fields map.</p>
    pub field_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ObjectTypeKey {
    /// <p>The types of keys that a ProfileObject can have. Each ProfileObject can have only 1 UNIQUE key but multiple PROFILE keys. PROFILE, ASSET, CASE, or ORDER means that this key can be used to tie an object to a PROFILE, ASSET, CASE, or ORDER respectively. UNIQUE means that it can be used to uniquely identify an object. If a key a is marked as SECONDARY, it will be used to search for profiles after all other PROFILE keys have been searched. A LOOKUP_ONLY key is only used to match a profile but is not persisted to be used for searching of the profile. A NEW_ONLY key is only used if the profile does not already exist before the object is ingested, otherwise it is only used for matching objects to profiles.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.standard_identifiers.is_none()`.
    pub fn standard_identifiers(&self) -> &[crate::types::StandardIdentifier] {
        self.standard_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>The reference for the key name of the fields map.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.field_names.is_none()`.
    pub fn field_names(&self) -> &[::std::string::String] {
        self.field_names.as_deref().unwrap_or_default()
    }
}
impl ObjectTypeKey {
    /// Creates a new builder-style object to manufacture [`ObjectTypeKey`](crate::types::ObjectTypeKey).
    pub fn builder() -> crate::types::builders::ObjectTypeKeyBuilder {
        crate::types::builders::ObjectTypeKeyBuilder::default()
    }
}

/// A builder for [`ObjectTypeKey`](crate::types::ObjectTypeKey).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ObjectTypeKeyBuilder {
    pub(crate) standard_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::StandardIdentifier>>,
    pub(crate) field_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ObjectTypeKeyBuilder {
    /// Appends an item to `standard_identifiers`.
    ///
    /// To override the contents of this collection use [`set_standard_identifiers`](Self::set_standard_identifiers).
    ///
    /// <p>The types of keys that a ProfileObject can have. Each ProfileObject can have only 1 UNIQUE key but multiple PROFILE keys. PROFILE, ASSET, CASE, or ORDER means that this key can be used to tie an object to a PROFILE, ASSET, CASE, or ORDER respectively. UNIQUE means that it can be used to uniquely identify an object. If a key a is marked as SECONDARY, it will be used to search for profiles after all other PROFILE keys have been searched. A LOOKUP_ONLY key is only used to match a profile but is not persisted to be used for searching of the profile. A NEW_ONLY key is only used if the profile does not already exist before the object is ingested, otherwise it is only used for matching objects to profiles.</p>
    pub fn standard_identifiers(mut self, input: crate::types::StandardIdentifier) -> Self {
        let mut v = self.standard_identifiers.unwrap_or_default();
        v.push(input);
        self.standard_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The types of keys that a ProfileObject can have. Each ProfileObject can have only 1 UNIQUE key but multiple PROFILE keys. PROFILE, ASSET, CASE, or ORDER means that this key can be used to tie an object to a PROFILE, ASSET, CASE, or ORDER respectively. UNIQUE means that it can be used to uniquely identify an object. If a key a is marked as SECONDARY, it will be used to search for profiles after all other PROFILE keys have been searched. A LOOKUP_ONLY key is only used to match a profile but is not persisted to be used for searching of the profile. A NEW_ONLY key is only used if the profile does not already exist before the object is ingested, otherwise it is only used for matching objects to profiles.</p>
    pub fn set_standard_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StandardIdentifier>>) -> Self {
        self.standard_identifiers = input;
        self
    }
    /// <p>The types of keys that a ProfileObject can have. Each ProfileObject can have only 1 UNIQUE key but multiple PROFILE keys. PROFILE, ASSET, CASE, or ORDER means that this key can be used to tie an object to a PROFILE, ASSET, CASE, or ORDER respectively. UNIQUE means that it can be used to uniquely identify an object. If a key a is marked as SECONDARY, it will be used to search for profiles after all other PROFILE keys have been searched. A LOOKUP_ONLY key is only used to match a profile but is not persisted to be used for searching of the profile. A NEW_ONLY key is only used if the profile does not already exist before the object is ingested, otherwise it is only used for matching objects to profiles.</p>
    pub fn get_standard_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StandardIdentifier>> {
        &self.standard_identifiers
    }
    /// Appends an item to `field_names`.
    ///
    /// To override the contents of this collection use [`set_field_names`](Self::set_field_names).
    ///
    /// <p>The reference for the key name of the fields map.</p>
    pub fn field_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.field_names.unwrap_or_default();
        v.push(input.into());
        self.field_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The reference for the key name of the fields map.</p>
    pub fn set_field_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.field_names = input;
        self
    }
    /// <p>The reference for the key name of the fields map.</p>
    pub fn get_field_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.field_names
    }
    /// Consumes the builder and constructs a [`ObjectTypeKey`](crate::types::ObjectTypeKey).
    pub fn build(self) -> crate::types::ObjectTypeKey {
        crate::types::ObjectTypeKey {
            standard_identifiers: self.standard_identifiers,
            field_names: self.field_names,
        }
    }
}

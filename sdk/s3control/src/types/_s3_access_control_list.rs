// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3AccessControlList {
    /// <p></p>
    pub owner: ::std::option::Option<crate::types::S3ObjectOwner>,
    /// <p></p>
    pub grants: ::std::option::Option<::std::vec::Vec<crate::types::S3Grant>>,
}
impl S3AccessControlList {
    /// <p></p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::S3ObjectOwner> {
        self.owner.as_ref()
    }
    /// <p></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.grants.is_none()`.
    pub fn grants(&self) -> &[crate::types::S3Grant] {
        self.grants.as_deref().unwrap_or_default()
    }
}
impl S3AccessControlList {
    /// Creates a new builder-style object to manufacture [`S3AccessControlList`](crate::types::S3AccessControlList).
    pub fn builder() -> crate::types::builders::S3AccessControlListBuilder {
        crate::types::builders::S3AccessControlListBuilder::default()
    }
}

/// A builder for [`S3AccessControlList`](crate::types::S3AccessControlList).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3AccessControlListBuilder {
    pub(crate) owner: ::std::option::Option<crate::types::S3ObjectOwner>,
    pub(crate) grants: ::std::option::Option<::std::vec::Vec<crate::types::S3Grant>>,
}
impl S3AccessControlListBuilder {
    /// <p></p>
    /// This field is required.
    pub fn owner(mut self, input: crate::types::S3ObjectOwner) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::S3ObjectOwner>) -> Self {
        self.owner = input;
        self
    }
    /// <p></p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::S3ObjectOwner> {
        &self.owner
    }
    /// Appends an item to `grants`.
    ///
    /// To override the contents of this collection use [`set_grants`](Self::set_grants).
    ///
    /// <p></p>
    pub fn grants(mut self, input: crate::types::S3Grant) -> Self {
        let mut v = self.grants.unwrap_or_default();
        v.push(input);
        self.grants = ::std::option::Option::Some(v);
        self
    }
    /// <p></p>
    pub fn set_grants(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::S3Grant>>) -> Self {
        self.grants = input;
        self
    }
    /// <p></p>
    pub fn get_grants(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::S3Grant>> {
        &self.grants
    }
    /// Consumes the builder and constructs a [`S3AccessControlList`](crate::types::S3AccessControlList).
    pub fn build(self) -> crate::types::S3AccessControlList {
        crate::types::S3AccessControlList {
            owner: self.owner,
            grants: self.grants,
        }
    }
}
